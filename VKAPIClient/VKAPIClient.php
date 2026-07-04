<?php

declare(strict_types=1);

namespace openvk\VKAPIClient;

/**
 * HTTP-клиент для реального VK API.
 *
 * В VK-proxy режиме (openvk.yml → openvk.vk.enabled = true)
 * токен берётся из зашифрованной куки vk_token, а не из конфига.
 *
 * Использование:
 *   $api = VKAPIClient::i();
 *   $users = $api->call("users.get", ["user_ids" => 1]);
 */
class VKAPIClient
{
    private const CIPHER = "aes-256-ctr";
    private const COOKIE_NAME = "vk_token";

    private string $apiUrl;
    private string $accessToken;
    private string $apiVersion;
    private bool $verifySsl;
    private int $cacheTtl;
    private string $cacheDir;

    /** @var array<string, array{data: array, time: int}> */
    private static array $responseCache = [];

    private static ?self $instance = null;

    /** @var string|null Последняя ошибка VK API для показа пользователю */
    private static ?string $lastErrorMessage = null;

    /**
     * Возвращает последнюю ошибку VK API.
     */
    public static function getLastErrorMessage(): ?string
    {
        return self::$lastErrorMessage;
    }

    /**
     * Очищает сохранённую ошибку.
     */
    public static function clearLastError(): void
    {
        self::$lastErrorMessage = null;
    }

    public function __construct(
        ?string $apiUrl = null,
        ?string $accessToken = null,
        ?string $apiVersion = null,
        ?bool $verifySsl = null,
        ?int $cacheTtl = null,
    ) {
        $vkConf = OPENVK_ROOT_CONF["openvk"]["vk"] ?? [];

        $this->apiUrl = rtrim(
            $apiUrl ?? ($vkConf["api_url"] ?? "https://api.vk.com/method"),
            "/",
        );
        $this->accessToken = $accessToken ?? ($vkConf["access_token"] ?? "");
        $this->apiVersion = $apiVersion ?? ($vkConf["api_version"] ?? "5.131");
        $this->verifySsl = $verifySsl ?? ($vkConf["verify_ssl"] ?? true);
        $this->cacheTtl = $cacheTtl ?? ($vkConf["cache_ttl"] ?? 300);

        // Директория для файлового кеша (между запросами)
        $this->cacheDir = OPENVK_ROOT . "/tmp/cache/vk_api";
        if (!is_dir($this->cacheDir)) {
            @mkdir($this->cacheDir, 0777, true);
        }
    }

    public static function i(): self
    {
        return self::$instance ?? (self::$instance = new self());
    }

    /**
     * Получает ключ шифрования на основе имени инстанса.
     */
    private static function getEncryptionKey(): string
    {
        $secret = OPENVK_ROOT_CONF["openvk"]["appearance"]["name"] ?? "OpenVK";

        return hash("sha256", $secret, true);
    }

    /**
     * Зашифровывает VK токен для хранения в куке.
     */
    public static function encryptToken(string $token): string
    {
        $iv        = openssl_random_pseudo_bytes(16);
        $encrypted = openssl_encrypt($token, self::CIPHER, self::getEncryptionKey(), OPENSSL_RAW_DATA, $iv);

        return base64_encode($iv . $encrypted);
    }

    /**
     * Расшифровывает VK токен из куки.
     * Возвращает null при ошибке.
     */
    public static function decryptToken(string $payload): ?string
    {
        $data = base64_decode($payload, true);
        if ($data === false || strlen($data) < 16) {
            return null;
        }

        $iv         = substr($data, 0, 16);
        $ciphertext = substr($data, 16);
        $result     = openssl_decrypt($ciphertext, self::CIPHER, self::getEncryptionKey(), OPENSSL_RAW_DATA, $iv);

        return $result === false ? null : $result;
    }

    /**
     * Пытается получить VK токен из куки.
     * Возвращает null, если кука отсутствует или не расшифровывается.
     */
    public static function getTokenFromCookie(): ?string
    {
        if (!isset($_COOKIE[self::COOKIE_NAME])) {
            return null;
        }

        return self::decryptToken($_COOKIE[self::COOKIE_NAME]);
    }

    /**
     * Определяет, какой токен использовать:
     * 1. Токен из куки (приоритет, для VK-proxy режима)
     * 2. Токен из конфига (fallback)
     */
    private function resolveAccessToken(): string
    {
        $cookieToken = self::getTokenFromCookie();
        if ($cookieToken !== null && $cookieToken !== "") {
            return $cookieToken;
        }

        return $this->accessToken;
    }

    /**
     * Получает кастомный api_url из куки (незашифрованный).
     * Если кука отсутствует, возвращает null.
     */
    public static function getApiUrlFromCookie(): ?string
    {
        if (!isset($_COOKIE["vk_api_url"])) {
            return null;
        }

        $url = trim($_COOKIE["vk_api_url"]);

        return $url !== "" ? $url : null;
    }

    /**
     * Определяет, какой api_url использовать:
     * 1. Из куки (приоритет)
     * 2. Из конфига (fallback)
     */
    private function resolveApiUrl(): string
    {
        $cookieUrl = self::getApiUrlFromCookie();
        if ($cookieUrl !== null) {
            return rtrim($cookieUrl, "/");
        }

        return $this->apiUrl;
    }

    /**
     * Строит ключ кеша по методу и параметрам.
     */
    private function buildCacheKey(string $method, array $params): string
    {
        ksort($params);

        return md5($method . ":" . serialize($params));
    }

    /**
     * Выполняет запрос к VK API с кешированием.
     *
     * @param string $method     Название метода (например, "users.get")
     * @param array  $params     Параметры запроса
     * @param string $httpMethod GET|POST
     * @return array Ответ VK API (ключ "response" или выбросит исключение)
     */
    public function call(
        string $method,
        array $params = [],
        string $httpMethod = "GET",
    ): array {

        bdump($method);
        bdump([...$params]);

        $params["access_token"] = $this->resolveAccessToken();
        $params["v"] = $this->apiVersion;

        // Auto-add minimal fields if not specified (avoids extra API calls for avatars)
        if (!isset($params["fields"]) && in_array($method, ["users.get", "groups.getById", "groups.get", "friends.get", "friends.getOnline", "groups.search", "users.search", "groups.getMembers"])) {
            $params["fields"] = "photo_50,photo_100";
        }

        // Проверка кеша (сначала in-memory, потом файловый)
        if ($this->cacheTtl > 0) {
            $cacheKey = $this->buildCacheKey($method, $params);

            // In-memory cache (время жизни — один запрос)
            if (isset(self::$responseCache[$cacheKey])) {
                $elapsed = time() - self::$responseCache[$cacheKey]["time"];
                if ($elapsed < $this->cacheTtl) {
                    bdump($cacheKey);
                    return self::$responseCache[$cacheKey]["data"];
                }

                unset(self::$responseCache[$cacheKey]);
            }

            // Файловый кеш (между запросами)
            $cacheFile = $this->cacheDir . "/" . $cacheKey . ".json";
            if (file_exists($cacheFile)) {
                $elapsed = time() - filemtime($cacheFile);
                if ($elapsed < $this->cacheTtl) {
                    $cached = json_decode(file_get_contents($cacheFile), true);
                    if ($cached !== null) {
                        self::$responseCache[$cacheKey] = ["data" => $cached, "time" => time()];
                        bdump($cacheKey);
                        return $cached;
                    }
                }

                @unlink($cacheFile);
            }
        }

        $result = $this->doRequest($method, $params, $httpMethod);

        // Сохранение в кеш
        if ($this->cacheTtl > 0 && isset($cacheKey)) {
            self::$responseCache[$cacheKey] = [
                "data" => $result,
                "time" => time(),
            ];

            // Файловый кеш
            @file_put_contents($cacheFile, json_encode($result));
        }

        return $result;
    }

    /**
     * Реальный HTTP-запрос к VK API.
     */
    private function doRequest(string $method, array $params, string $httpMethod): array
    {
        $url = $this->resolveApiUrl() . "/" . $method;

        $ch = curl_init();

        if (strtoupper($httpMethod) === "POST") {
            curl_setopt_array($ch, [
                CURLOPT_URL => $url,
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => http_build_query($params),
            ]);
        } else {
            $url .= "?" . http_build_query($params);
            curl_setopt_array($ch, [
                CURLOPT_URL => $url,
                CURLOPT_HTTPGET => true,
            ]);
        }

        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_USERAGENT => "chrome",
            CURLOPT_HTTPHEADER => ["Accept: application/json"],
        ]);

        if ($this->verifySsl) {
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);

            $caBundle = null;
            if (PHP_SHLIB_SUFFIX === "dll") {
                $possiblePaths = [
                    __DIR__ . "/cacert.pem",
                    PHP_BINARY . "/../extras/ssl/cacert.pem",
                    PHP_BINARY . "/../ssl/cacert.pem",
                    "C:\\php\\extras\\ssl\\cacert.pem",
                    "C:\\php\\ssl\\cacert.pem",
                    "C:\\tools\\php\\extras\\ssl\\cacert.pem",
                    "C:\\tools\\php\\ssl\\cacert.pem",
                ];

                foreach ($possiblePaths as $path) {
                    if (file_exists($path)) {
                        $caBundle = $path;
                        break;
                    }
                }
            }

            if ($caBundle) {
                curl_setopt($ch, CURLOPT_CAINFO, $caBundle);
            }
        } else {
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
        }

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        curl_close($ch);

        if ($response === false) {
            $sslHint = "";
            if (str_contains($curlError, "SSL")) {
                $sslHint = " (SSL error. Add 'verify_ssl: false' to openvk.yml under 'vk:' section, or install a CA bundle)";
            }

            self::$lastErrorMessage = "cURL error: " . $curlError . $sslHint;
            throw new VKAPIException(self::$lastErrorMessage);
        }

        $decoded = json_decode($response, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            self::$lastErrorMessage = "JSON parse error: " . json_last_error_msg();
            throw new VKAPIException(self::$lastErrorMessage);
        }

        if (isset($decoded["error"])) {
            $err = $decoded["error"];
            self::$lastErrorMessage = "VK API error [{$err["error_code"]}]: {$err["error_msg"]}";
            throw new VKAPIException(
                self::$lastErrorMessage,
                (int) $err["error_code"],
            );
        }

        return $decoded["response"] ?? [];
    }

    /**
     * Очищает кеш ответов.
     */
    public static function clearCache(?string $method = null): void
    {
        if ($method === null) {
            self::$responseCache = [];
        } else {
            foreach (self::$responseCache as $key => $cached) {
                if (str_starts_with($key, md5($method . ":"))) {
                    unset(self::$responseCache[$key]);
                }
            }
        }
    }

    /**
     * Обёртка для users.get
     *
     * @see https://dev.vk.com/method/users.get
     */
    public function usersGet(array|int $userIds, array $fields = []): array
    {
        return $this->call("users.get", [
            "user_ids" => implode(",", (array) $userIds),
            "fields" => implode(",", $fields),
        ]);
    }

    /**
     * Обёртка для groups.getById
     *
     * @see https://dev.vk.com/method/groups.getById
     */
    public function groupsGetById(
        array|int $groupIds,
        array $fields = [],
    ): array {
        return $this->call("groups.getById", [
            "group_ids" => implode(",", (array) $groupIds),
            "fields" => implode(",", $fields),
        ]);
    }

    /**
     * Обёртка для groups.get (список групп пользователя)
     *
     * @see https://dev.vk.com/method/groups.get
     */
    public function groupsGet(
        int $userId,
        array $fields = [],
        int $count = 50,
        int $offset = 0,
    ): array {
        return $this->call("groups.get", [
            "user_id" => $userId,
            "extended" => 1,
            "fields" => implode(",", $fields),
            "count" => $count,
            "offset" => $offset,
        ]);
    }

    /**
     * Обёртка для wall.get
     *
     * @see https://dev.vk.com/method/wall.get
     */
    public function wallGet(
        int|string $ownerId,
        int $count = 20,
        int $offset = 0,
        array $extra = [],
    ): array {
        return $this->call(
            "wall.get",
            array_merge($extra, [
                "owner_id" => $ownerId,
                "count" => $count,
                "offset" => $offset,
            ]),
        );
    }

    /**
     * Обёртка для newsfeed.get
     *
     * @see https://dev.vk.com/method/newsfeed.get
     */
    public function newsfeedGet(
        array $filters = ["post"],
        int $count = 30,
        array $extra = [],
    ): array {
        return $this->call(
            "newsfeed.get",
            array_merge($extra, [
                "filters" => implode(",", $filters),
                "count" => $count,
            ]),
        );
    }

    public function setAccessToken(string $token): void
    {
        $this->accessToken = $token;
    }

    public function getAccessToken(): string
    {
        return $this->accessToken;
    }

    public function getApiUrl(): string
    {
        return $this->apiUrl;
    }

    public function getApiVersion(): string
    {
        return $this->apiVersion;
    }
}
