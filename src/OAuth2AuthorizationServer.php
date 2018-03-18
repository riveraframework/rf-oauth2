<?php
/**
 * This file is part of the Rivera Framework OAuth2 package.
 *
 * (c) Pierre-Julien Mazenot <pj.mazenot@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Rf\OAuth2;

use App\Entities\Repositories\OAuth2AccessTokenRepository;
use App\Entities\Repositories\OAuth2AuthCodeRepository;
use App\Entities\Repositories\OAuth2ClientRepository;
use App\Entities\Repositories\OAuth2RefreshTokenRepository;
use App\Entities\Repositories\OAuth2ScopeRepository;
use App\Entities\Repositories\OAuth2UserRepository;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Grant\AuthCodeGrant;
use League\OAuth2\Server\Grant\ClientCredentialsGrant;
use Rf\OAuth2\Grants\PasswordGrant;
use Rf\OAuth2\Grants\PlainRefreshTokenGrant;
use Rf\OAuth2\Responses\Psr7Response;

/**
 * Class OAuth2AuthorizationServer
 *
 * @TODO: Put default key files in Rf
 *
 * @package Rf\OAuth2
 */
class OAuth2AuthorizationServer {

    /** @var string Path to the private key file */
    protected $privateKeyPath;

    /** @var string Encryption key */
    protected $encryptionKey = 'VloMgtipozYQAcUVNPlKx+COaJsW9LcVqPFFaBjNy7Q=';

    /** @var AuthorizationServer Main service */
    protected $service;

    /**
     * Use a custom private key
     *
     * @param $privateKeyPath
     */
    public function setPrivateKey($privateKeyPath) {

        $this->privateKeyPath = $privateKeyPath;

    }

    /**
     * Set the encryption key
     *
     * @param $encryptionKey
     */
    public function setEncryptionKey($encryptionKey) {

        $this->encryptionKey = $encryptionKey;

    }

    /**
     * Get the authorization service
     *
     * @return AuthorizationServer
     * @throws \Exception
     */
    public function getService() {

        if(empty($this->service)) {

            // Init our repositories
            $clientRepository = new OAuth2ClientRepository();
            $scopeRepository = new OAuth2ScopeRepository();
            $accessTokenRepository = new OAuth2AccessTokenRepository();
            $authCodeRepository = new OAuth2AuthCodeRepository();
            $refreshTokenRepository = new OAuth2RefreshTokenRepository();
            $userRepository = new OAuth2UserRepository();

            $privateKey = rf_dir('config') . 'security/oauth2-private.key';
            if(!empty($this->privateKeyPath)) {
                $privateKey = $this->privateKeyPath;
            }

            if(!file_exists($this->privateKeyPath)) {
                throw new \Exception('The private key is invalid (file not found: ' . $this->privateKeyPath . ')');
            }

            // Init response
            $responseType = rf_request()->getPostData()->get('type');
            if ($responseType == 'bearer') {
                $response = null;
            } else {
                $response = new Psr7Response();
            }

            // Setup the authorization server
            $server = new AuthorizationServer(
                $clientRepository,
                $accessTokenRepository,
                $scopeRepository,
                $privateKey,
                $this->encryptionKey,
                $response
            );

            // Define default ttl in case it's omitted in config file
            $defaultAuthCodeTtl = new \DateInterval('PT10M'); // authorization codes will expire after 10 minutes
            $defaultAccessTokenTtl = new \DateInterval('PT1H'); // access tokens will expire after 1 hour
            $refreshAccessTokenTtl = new \DateInterval('P1M'); // refresh tokens will expire after 1 month

            // Add support for authorization code grant
            $settings = rf_config('oauth2');

            if (empty($settings)) {
                return $server;
            } else {
                $settings = $settings->toArray();
            }

            if (!empty($settings['grants']['authorization_code']['activated'])) {

                $grant = new AuthCodeGrant(
                    $authCodeRepository,
                    $refreshTokenRepository,
                    (!empty($settings['grants']['authorization_code']['auth_code_ttl'])
                        ? $settings['grants']['authorization_code']['auth_code_ttl']
                        : $defaultAuthCodeTtl
                    )
                );

                $grant->setRefreshTokenTTL(
                    !empty($settings['grants']['authorization_code']['refresh_token_ttl'])
                        ? $settings['grants']['authorization_code']['refresh_token_ttl']
                        : $refreshAccessTokenTtl
                );

                // Enable the authentication code grant on the server
                $server->enableGrantType(
                    $grant,
                    (!empty($settings['grants']['authorization_code']['access_token_ttl'])
                        ? $settings['grants']['authorization_code']['access_token_ttl']
                        : $defaultAccessTokenTtl
                    )
                );

            }

            // Add support for client credentials grant
            if (!empty($settings['grants']['client_credentials']['activated'])) {

                $clientCredentialGrant = new ClientCredentialsGrant();

                // Enable the client credentials grant on the server
                $server->enableGrantType(
                    $clientCredentialGrant,
                    (!empty($settings['grants']['client_credentials']['access_token_ttl'])
                        ? $settings['grants']['client_credentials']['access_token_ttl']
                        : $defaultAccessTokenTtl
                    )
                );

            }

            // Add support for refresh token grant
            if (!empty($settings['grants']['refresh_token']['activated'])) {

                $grant = new PlainRefreshTokenGrant($refreshTokenRepository);

                $grant->setRefreshTokenTTL(
                    !empty($settings['grants']['refresh_token']['refresh_token_ttl'])
                        ? $settings['grants']['refresh_token']['refresh_token_ttl']
                        : $refreshAccessTokenTtl
                );

                // Enable the refresh token grant on the server
                $server->enableGrantType(
                    $grant,
                    (!empty($settings['grants']['refresh_token']['access_token_ttl'])
                        ? $settings['grants']['refresh_token']['access_token_ttl']
                        : $defaultAccessTokenTtl
                    )
                );

            }

            // Add support for password grant
            if (!empty($settings['grants']['password']['activated'])) {

                $grant = new PasswordGrant(
                    $userRepository,
                    $refreshTokenRepository
                );

                $grant->setRefreshTokenTTL(
                    !empty($settings['grants']['password']['refresh_token_ttl'])
                        ? $settings['grants']['password']['refresh_token_ttl']
                        : $refreshAccessTokenTtl
                );

                // Enable the password grant on the server
                $server->enableGrantType(
                    $grant,
                    (!empty($settings['grants']['password']['access_token_ttl'])
                        ? $settings['grants']['password']['access_token_ttl']
                        : $defaultAccessTokenTtl
                    )
                );

            }

            $this->service = $server;

        }

        return $this->service;

    }

}