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

use App\Entities\Classes\C_default\OAuth2AccessToken;
use App\Entities\Classes\C_default\OAuth2RefreshToken;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\RefreshTokenGrant;
use League\OAuth2\Server\RequestEvent;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Class PlainRefreshTokenGrant
 *
 * @TODO: Replace Entities by interfaces
 *
 * @package App\OAuth2\Classes
 */
class PlainRefreshTokenGrant extends RefreshTokenGrant {

    /**
     * @param ServerRequestInterface $request
     * @param string                 $clientId
     *
     * @throws OAuthServerException
     *
     * @return array
     */
    protected function validateOldRefreshToken(ServerRequestInterface $request, $clientId) {

        $encryptedRefreshToken = $this->getRequestParameter('refresh_token', $request);
        if (is_null($encryptedRefreshToken)) {
            throw OAuthServerException::invalidRequest('refresh_token');
        }

        // Validate refresh token
        try {

            $refreshToken = $this->decrypt($encryptedRefreshToken);

            return parent::validateOldRefreshToken($request, $clientId);

        } catch (\LogicException $e) {

            /** @var AbstractOAuth2RefreshToken $oauth2RefreshToken */
            $oauth2RefreshToken = AbstractOAuth2RefreshToken::findFirstBy('refresh_token = "' . $encryptedRefreshToken . '"');

            if (!$oauth2RefreshToken) {
                throw OAuthServerException::invalidRefreshToken('Cannot decrypt the refresh token');
            }

        }

        /** @var OAuth2AccessToken $oauth2AccessToken */
        $oauth2AccessToken = OAuth2AccessToken::findFirstBy('id = ' . $oauth2RefreshToken->getOauth2AccessTokenId());

        // Get session
        $session = $oauth2AccessToken->getSession();

        // Get token scopes
        $scopes = [];
        foreach ($oauth2AccessToken->getScopes() as $scope) {
            $scopes[] = $scope->getScope();
        }

        $refreshTokenData = [
            'client_id' => $session->getOauth2ClientId(),
            'refresh_token_id' => $oauth2RefreshToken->getIdentifier(),
            'access_token_id' => $oauth2AccessToken->getIdentifier(),
            'scopes' => $scopes,
            'user_id' => $session->getOauth2UserId(),
        ];

        if ($refreshTokenData['client_id'] !== $clientId) {
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::REFRESH_TOKEN_CLIENT_FAILED, $request));
            throw OAuthServerException::invalidRefreshToken('Token is not linked to client');
        }

        $nowDateTime = new \DateTime();

        if($nowDateTime > $oauth2RefreshToken->getExpiryDateTime()) {
            throw OAuthServerException::accessDenied('Token is expired');
        }

        if ($this->refreshTokenRepository->isRefreshTokenRevoked($refreshTokenData['refresh_token_id']) === true) {
            throw OAuthServerException::invalidRefreshToken('Token has been revoked');
        }

        return $refreshTokenData;
    }

}
