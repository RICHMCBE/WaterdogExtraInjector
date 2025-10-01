<?php

declare(strict_types=1);

namespace alvin0319\WaterdogExtraInjector\network\handler;

use Closure;
use InvalidArgumentException;
use pocketmine\entity\InvalidSkinException;
use pocketmine\event\player\PlayerPreLoginEvent;
use pocketmine\lang\KnownTranslationFactory;
use pocketmine\network\mcpe\convert\TypeConverter;
use pocketmine\network\mcpe\handler\PacketHandler;
use pocketmine\network\mcpe\JwtException;
use pocketmine\network\mcpe\JwtUtils;
use pocketmine\network\mcpe\NetworkSession;
use pocketmine\network\mcpe\protocol\LoginPacket;
use pocketmine\network\mcpe\protocol\types\skin\PersonaPieceTintColor;
use pocketmine\network\mcpe\protocol\types\skin\PersonaSkinPiece;
use pocketmine\network\mcpe\protocol\types\skin\SkinAnimation;
use pocketmine\network\mcpe\protocol\types\skin\SkinData;
use pocketmine\network\mcpe\protocol\types\skin\SkinImage;
use pocketmine\network\PacketHandlingException;
use pocketmine\player\Player;
use pocketmine\player\PlayerInfo;
use pocketmine\player\XboxLivePlayerInfo;
use pocketmine\Server;
use Ramsey\Uuid\Uuid;
use function array_map;
use function base64_decode;
use function is_array;
use function json_decode;
use function property_exists;

final class WDPELoginPacketHandler extends PacketHandler{

	private Server $server;
	private NetworkSession $session;
	/**
	 * @var Closure
	 * @phpstan-var Closure(PlayerInfo) : void
	 */
	private Closure $playerInfoConsumer;
	/**
	 * @var Closure
	 * @phpstan-var Closure(bool, bool, ?string, ?string) : void
	 */
	private Closure $authCallback;

	/**
	 * @phpstan-param Closure(PlayerInfo) : void $playerInfoConsumer
	 * @phpstan-param Closure(bool $isAuthenticated, bool $authRequired, ?string $error, ?string $clientPubKey) : void $authCallback
	 */
	public function __construct(Server $server, NetworkSession $session, Closure $playerInfoConsumer, Closure $authCallback){
		$this->session = $session;
		$this->server = $server;
		$this->playerInfoConsumer = $playerInfoConsumer;
		$this->authCallback = $authCallback;
	}

	public function handleLogin(LoginPacket $packet) : bool{
		// API 5에서는 chainDataJwt 또는 authInfoJson 사용
		$chainData = null;
		if(property_exists($packet, 'chainDataJwt') && isset($packet->chainDataJwt)){
			// 새로운 API 5 방식
			$chainData = $packet->chainDataJwt->chain ?? null;
		}elseif(property_exists($packet, 'authInfoJson') && isset($packet->authInfoJson)){
			// 이전 방식
			$chainData = $this->parseChainDataFromJson($packet->authInfoJson);
		}else{
			$this->server->getLogger()->warning("[WDPE Debug] No chain data property found in LoginPacket");
		}

		if($chainData === null){
			throw new PacketHandlingException("Failed to extract chain data from LoginPacket");
		}

        $extraData = $this->fetchAuthData($chainData);

		$displayName = $extraData->displayName ?? $extraData->name ?? null;
		
		if($displayName === null || !Player::isValidUserName($displayName)){
			$this->session->disconnectWithError(KnownTranslationFactory::disconnectionScreen_invalidName());
			return true;
		}

		$clientData = $this->parseWDPEClientData($packet->clientDataJwt);

		(function() use ($clientData) : void{
			$this->ip = $clientData->Waterdog_IP;
		})->call($this->session);

		try{
			$skin = TypeConverter::getInstance()->getSkinAdapter()->fromSkinData(self::fromClientData($clientData));
		}catch(InvalidArgumentException|InvalidSkinException $e){
			$this->session->getLogger()->debug("Invalid skin: " . $e->getMessage());
			$this->session->disconnectWithError(KnownTranslationFactory::disconnectionScreen_invalidSkin());
			return true;
		}

		$identityUuid = $extraData->identity ?? $extraData->UUID ?? $extraData->uuid ?? null;
		
		if($identityUuid === null || !Uuid::isValid($identityUuid)){
			throw new PacketHandlingException("Invalid login UUID");
		}
		$uuid = Uuid::fromString($identityUuid);
		if($clientData->Waterdog_XUID !== ""){
			$playerInfo = new XboxLivePlayerInfo(
				$clientData->Waterdog_XUID,
				$displayName,
				$uuid,
				$skin,
				$clientData->LanguageCode,
				(array) $clientData
			);
		}else{
			$playerInfo = new PlayerInfo(
				$displayName,
				$uuid,
				$skin,
				$clientData->LanguageCode,
				(array) $clientData
			);
		}
		($this->playerInfoConsumer)($playerInfo);

		Closure::bind(
			closure: function(NetworkSession $session) use ($playerInfo) : void{
				$session->info = $playerInfo;
			},
			newThis: $this,
			newScope: NetworkSession::class
		)($this->session);

		$ev = new PlayerPreLoginEvent(
			$playerInfo,
			$this->session->getIp(),
			$this->session->getPort(),
			$this->server->requiresAuthentication()
		);
		if($this->server->getNetwork()->getValidConnectionCount() > $this->server->getMaxPlayers()){
			$ev->setKickFlag(PlayerPreLoginEvent::KICK_FLAG_SERVER_FULL, KnownTranslationFactory::disconnectionScreen_serverFull());
		}
		if(!$this->server->isWhitelisted($playerInfo->getUsername())){
			$ev->setKickFlag(PlayerPreLoginEvent::KICK_FLAG_SERVER_WHITELISTED, KnownTranslationFactory::pocketmine_disconnect_whitelisted());
		}

		$banMessage = null;
		if(($banEntry = $this->server->getNameBans()->getEntry($playerInfo->getUsername())) !== null){
			$banReason = $banEntry->getReason();
			$banMessage = $banReason === "" ? KnownTranslationFactory::pocketmine_disconnect_ban_noReason() : KnownTranslationFactory::pocketmine_disconnect_ban($banReason);
		}elseif(($banEntry = $this->server->getIPBans()->getEntry($this->session->getIp())) !== null){
			$banReason = $banEntry->getReason();
			$banMessage = KnownTranslationFactory::pocketmine_disconnect_ban($banReason !== "" ? $banReason : KnownTranslationFactory::pocketmine_disconnect_ban_ip());
		}
		if($banMessage !== null){
			$ev->setKickFlag(PlayerPreLoginEvent::KICK_FLAG_BANNED, $banMessage);
		}

		$ev->call();
		if(!$ev->isAllowed()){
			$this->session->disconnect($ev->getFinalDisconnectReason(), $ev->getFinalDisconnectScreenMessage());
			return true;
		}

		$this->processLogin($packet, $ev->isAuthRequired(), $chainData);

		return true;
	}

	/**
	 * @throws PacketHandlingException
	 * @return string[]
	 */
	private function parseChainDataFromJson(string $authInfoJson): array {
		try {
			$authInfo = json_decode($authInfoJson, true);
			if (!is_array($authInfo)) {
				throw new PacketHandlingException("Invalid auth info JSON");
			}

			$chainArray = null;

			// Certificate 내부의 chain 확인
			if (isset($authInfo['Certificate'])) {
				$certificate = json_decode($authInfo['Certificate'], true);
				if (is_array($certificate)) {
					if (isset($certificate['chain']) && is_array($certificate['chain'])) {
						$chainArray = $certificate['chain'];
					}
				}
			}

			// 직접 chain 확인 (fallback)
			if ($chainArray === null && isset($authInfo['chain']) && is_array($authInfo['chain'])) {
				$chainArray = $authInfo['chain'];
			}

			if ($chainArray === null) {
				throw new PacketHandlingException("No chain data found in auth info");
			}

			return $chainArray;

		} catch (\JsonException $e) {
			throw PacketHandlingException::wrap($e);
		}
	}

	/**
	 * @throws PacketHandlingException
	 */
	protected function fetchAuthData(array $chain) : object{
		$extraData = null;
		foreach($chain as $k => $jwt){
			try{
				[, $claims,] = JwtUtils::parse($jwt);
			}catch(JwtException $e){
				throw PacketHandlingException::wrap($e);
			}
			if(isset($claims["extraData"])){
				if($extraData !== null){
					throw new PacketHandlingException("Found 'extraData' more than once in chainData");
				}

				if(!is_array($claims["extraData"])){
					throw new PacketHandlingException("'extraData' key should be an array");
				}
				
				$extraData = (object) $claims["extraData"];
			}
		}
		if($extraData === null){
			throw new PacketHandlingException("'extraData' not found in chain data");
		}
		return $extraData;
	}

	/**
	 * @throws PacketHandlingException
	 */
	protected function parseWDPEClientData(string $clientDataJwt) : WDPEClientData{
		try{
			[, $clientDataClaims,] = JwtUtils::parse($clientDataJwt);
		}catch(JwtException $e){
			throw PacketHandlingException::wrap($e);
		}

		// WDPEClientData 객체 생성 및 속성 직접 할당
		$clientData = new WDPEClientData();
		$reflection = new \ReflectionClass($clientData);
		foreach($clientDataClaims as $key => $value){
			if($reflection->hasProperty($key)){
				$property = $reflection->getProperty($key);
				// static 속성은 건너뛰기
				if(!$property->isStatic()){
					$clientData->$key = $value;
				}
			}
		}
		
		return $clientData;
	}

	/**
	 * @param string[] $chainData
	 */
	protected function processLogin(LoginPacket $packet, bool $authRequired, array $chainData) : void{
		// WaterdogPE에서 이미 인증되었으므로 authenticated=true로 설정
		// chain에서 identityPublicKey 추출
		$clientPubKey = null;
		try{
			if(count($chainData) > 0){
				// 마지막 chain에서 identityPublicKey 추출
				$lastChain = end($chainData);
				[, $claims,] = JwtUtils::parse($lastChain);
				if(isset($claims["identityPublicKey"])){
					$clientPubKey = $claims["identityPublicKey"];
				}
			}
		}catch(\Exception $e){
			$this->server->getLogger()->debug("Failed to extract client public key: " . $e->getMessage());
		}
		
		($this->authCallback)(true, $authRequired, null, $clientPubKey);
	}

	private static function safeB64Decode(string $base64, string $context) : string{
		$result = base64_decode($base64, true);
		if($result === false){
			throw new InvalidArgumentException("$context: Malformed base64, cannot be decoded");
		}
		return $result;
	}

	public static function fromClientData(WDPEClientData $clientData) : SkinData{
		/** @var SkinAnimation[] $animations */
		$animations = [];
		foreach($clientData->AnimatedImageData as $k => $animation){
			// 배열이면 객체로 변환
			if(is_array($animation)){
				$animation = (object) $animation;
			}
			$animations[] = new SkinAnimation(
				new SkinImage(
					$animation->ImageHeight,
					$animation->ImageWidth,
					self::safeB64Decode($animation->Image, "AnimatedImageData.$k.Image")
				),
				$animation->Type,
				$animation->Frames,
				$animation->AnimationExpression
			);
		}
		
		// PersonaPieces와 PieceTintColors도 배열이면 객체로 변환
		$personaPieces = array_map(function($piece) : PersonaSkinPiece{
			if(is_array($piece)){
				$piece = (object) $piece;
			}
			return new PersonaSkinPiece($piece->PieceId, $piece->PieceType, $piece->PackId, $piece->IsDefault, $piece->ProductId);
		}, $clientData->PersonaPieces);
		
		$pieceTintColors = array_map(function($tint) : PersonaPieceTintColor{
			if(is_array($tint)){
				$tint = (object) $tint;
			}
			return new PersonaPieceTintColor($tint->PieceType, $tint->Colors);
		}, $clientData->PieceTintColors);
		
		return new SkinData(
			$clientData->SkinId,
			$clientData->PlayFabId,
			self::safeB64Decode($clientData->SkinResourcePatch, "SkinResourcePatch"),
			new SkinImage($clientData->SkinImageHeight, $clientData->SkinImageWidth, self::safeB64Decode($clientData->SkinData, "SkinData")),
			$animations,
			new SkinImage($clientData->CapeImageHeight, $clientData->CapeImageWidth, self::safeB64Decode($clientData->CapeData, "CapeData")),
			self::safeB64Decode($clientData->SkinGeometryData, "SkinGeometryData"),
			self::safeB64Decode($clientData->SkinGeometryDataEngineVersion, "SkinGeometryDataEngineVersion"),
			self::safeB64Decode($clientData->SkinAnimationData, "SkinAnimationData"),
			$clientData->CapeId,
			null,
			$clientData->ArmSize,
			$clientData->SkinColor,
			$personaPieces,
			$pieceTintColors,
			true,
			$clientData->PremiumSkin,
			$clientData->PersonaSkin,
			$clientData->CapeOnClassicSkin,
			true,
		);
	}
}
