<?php
/**
 * This file is part of the Rivera Framework OAuth2 package.
 *
 * (c) Pierre-Julien Mazenot <pj.mazenot@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Rf\OAuth2\Grants;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\AbstractGrant;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Class PasswordGrant
 * 
 * @package Rf\OAuth2\Grants
 */
class PasswordGrant extends AbstractGrant {

    /**
     * PasswordGrant constructor.
     *
     * @param UserRepositoryInterface $userRepository
     * @param RefreshTokenRepositoryInterface $refreshTokenRepository
     *
     * @throws \Exception
     */
    public function __construct(
        UserRepositoryInterface $userRepository,
        RefreshTokenRepositoryInterface $refreshTokenRepository
    ) {

        $this->setUserRepository($userRepository);
        $this->setRefreshTokenRepository($refreshTokenRepository);

        $this->refreshTokenTTL = new \DateInterval('P1M');

    }

    /**
     * {@inheritdoc}
     */
    public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        \DateInterval $accessTokenTTL
    ) {

        // Validate request
        $client = $this->validateClient($request);
        $scopes = $this->validateScopes($this->getRequestParameter('scope', $request));
        $user = $this->validateUser($request, $client);

        // Finalize the requested scopes
        $scopes = $this->scopeRepository->finalizeScopes($scopes, $this->getIdentifier(), $client, $user->getIdentifier());

        // Issue and persist new tokens
        $accessToken = $this->issueAccessToken($accessTokenTTL, $client, $user->getIdentifier(), $scopes);
        $refreshToken = $this->issueRefreshToken($accessToken);

        // Inject tokens into response
        $responseType->setAccessToken($accessToken);
        $responseType->setRefreshToken($refreshToken);

        return $responseType;

    }

    /**
     * @param ServerRequestInterface $request
     * @param ClientEntityInterface  $client
     *
     * @throws OAuthServerException
     * @throws \Exception
     *
     * @return UserEntityInterface
     */
    protected function validateUser(ServerRequestInterface $request, ClientEntityInterface $client) {

        $username = $this->getRequestParameter('username', $request);
        if (is_null($username)) {
            throw OAuthServerException::invalidRequest('username');
        }

        $password = $this->getRequestParameter('password', $request);
        if (is_null($password)) {
            throw OAuthServerException::invalidRequest('password');
        }

        try {

	        $user = $this->userRepository->getUserEntityByUserCredentials(
		        $username,
		        $password,
		        $this->getIdentifier(),
		        $client
	        );

        } catch (\Exception $e) {

        	$this->getEmitter()->emit(new RequestEvent(RequestEvent::USER_AUTHENTICATION_FAILED, $request));

	        throw $e;

        }

        return $user;

    }

    /**
     * {@inheritdoc}
     */
    public function getIdentifier() {

        return 'password';

    }

}
