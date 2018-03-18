<?php
/**
 * This file is part of the Rivera Framework OAuth2 package.
 *
 * (c) Pierre-Julien Mazenot <pj.mazenot@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Rf\OAuth2\Responses;

use App\Entities\Classes\C_default\OAuth2AccessToken;
use App\Entities\Classes\C_default\OAuth2RefreshToken;
use GuzzleHttp\Psr7\Response as GuzzlePsr7Response;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\CryptTrait;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Class Psr7Response
 *
 * @package App\Common\Classes\Responses
 */
class Psr7Response extends GuzzlePsr7Response implements ResponseTypeInterface {

    use CryptTrait;

    /** @var OAuth2AccessToken $accessToken */
    protected $accessToken;

    /** @var OAuth2RefreshToken $refreshToken */
    protected $refreshToken;

    /** @var CryptKey */
    protected $privateKey;

    /** @var string */
    protected $encryptionKey;

    public function getAccessToken() {

        return $this->accessToken;

    }

    /**
     * @param AccessTokenEntityInterface $accessToken
     */
    public function setAccessToken(AccessTokenEntityInterface $accessToken) {

        $this->accessToken = $accessToken;

    }

    public function getRefreshToken() {

        return $this->refreshToken;

    }

    /**
     * @param RefreshTokenEntityInterface $refreshToken
     */
    public function setRefreshToken(RefreshTokenEntityInterface $refreshToken) {

        $this->refreshToken = $refreshToken;

    }

    /**
     * Set the private key
     *
     * @param \League\OAuth2\Server\CryptKey $key
     */
    public function setPrivateKey(CryptKey $key)
    {
        $this->privateKey = $key;
    }

    /**
     * Set the encryption key
     *
     * @param string $key
     */
    public function setEncryptionKey($key = null)
    {
        $this->encryptionKey = $key;
    }

    /**
     * @param ResponseInterface $response
     *
     * @return ResponseInterface
     */
    public function generateHttpResponse(ResponseInterface $response) {

        $expireDateTime = $this->accessToken->getExpiryDateTime()->getTimestamp();

        $responseParams = [
            'token_type'   => 'Plain',
            'expires_in'   => $expireDateTime - (new \DateTime())->getTimestamp(),
            'access_token' => (string) $this->accessToken->getIdentifier(),
        ];

        if ($this->refreshToken instanceof RefreshTokenEntityInterface) {

            $responseParams['refresh_token'] = (string)$this->refreshToken->getIdentifier();

        }

        $response = $response
            ->withStatus(200)
            ->withHeader('pragma', 'no-cache')
            ->withHeader('cache-control', 'no-store')
            ->withHeader('content-type', 'application/json; charset=UTF-8');

        $response->getBody()->write(json_encode($responseParams));

        return $response;

    }

}