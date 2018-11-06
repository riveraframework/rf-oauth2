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

use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Exception\ServerException;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\GenericProvider;
use League\OAuth2\Client\Token\AccessToken;
//use Rf\OAuth2\Authentication;
use Rf\Core\Http\Curl;
use Rf\Core\Session\Cookie;
use Rf\Core\Utils\Format\Json;

/**
 * Class OAuth2Client
 */
class OAuth2Client {

	/** @var string $clientId */
	public $clientId;

	/** @var GenericProvider $provider */
	public $provider;

	/** @var string $grantType */
	public $grantType;

	/** @var string $authParams */
	public $authParams;

	/** @var AccessToken */
	public $accessToken;

	/**
	 * ExampleOAuth2Client constructor
	 *
	 * @param string $clientId
	 * @param string $clientSecret
	 * @param string $grantType
	 * @param array $authParams
	 */
	public function __construct($clientId, $clientSecret, $grantType = null, $authParams = []) {

		$this->clientId = $clientId;

		if(
		    empty($authParams['redirectUri'])
		    || empty($authParams['urlAuthorize'])
		    || empty($authParams['urlAccessToken'])
		    || empty($authParams['urlResourceOwnerDetails'])
        ) {
            throw new \Exception('Missing urls : redirectUri, urlAuthorize, urlAccessToken and 
                                urlResourceOwnerDetails required in $authParams');
        }

		// Note: the GenericProvider requires the `urlAuthorize` option, even though
		// it's not used in the OAuth 2.0 client credentials grant type.
		$this->provider = new GenericProvider([
			'clientId'                => $clientId,
			'clientSecret'            => $clientSecret,
			'redirectUri'             => $authParams['redirectUri'],
			'urlAuthorize'            => $authParams['urlAuthorize'],
			'urlAccessToken'          => $authParams['urlAccessToken'],
			'urlResourceOwnerDetails' => $authParams['urlResourceOwnerDetails'],
		]);

		if(isset($grantType)) {
			$this->grantType = $grantType;
		}

		$this->authParams = $authParams;

	}

	/**
	 * Get provider
	 *
	 * @return GenericProvider
	 * @throws \Exception
	 */
	public function getProvider() {

		if(!isset($this->provider)) {
			throw new \Exception('No provider available');
		}

		return $this->provider;

	}

	/**
	 * Get access token
	 *
	 * @param string|null $cacheMode
	 *
	 * @return AccessToken
	 */
	public function getAccessToken($cacheMode = null) {

		if(isset($this->accessToken)) {

			return $this->accessToken;

		} else {

			$cacheToken = $this->getCachedToken($cacheMode);

			if(!$cacheToken) {

			    return $this->requestNewToken($cacheMode);

			} else {

				$this->accessToken = $cacheToken;

				return $this->accessToken;

			}

		}

	}

    /**
     * Refresh access token
     *
     * @param string|null $cacheMode
     *
     * @return AccessToken
     */
	public function refreshAccessToken($cacheMode = null) {

        return $this->requestNewToken($cacheMode);

    }

    /**
     * @param string|null $cacheMode
     *
     * @return AccessToken
     * @throws \Exception
     */
	protected function requestNewToken($cacheMode = null) {

        try {

        	$this->clearAll();

            // Try to get an access token using the client credentials grant.
            $accessToken = $this->getProvider()->getAccessToken($this->grantType, $this->authParams);

            if(!is_a($accessToken, AccessToken::class)) {
            	throw new \Exception($accessToken);
            }

            $this->accessToken = $accessToken;
            $this->setCachedToken($this->accessToken, $cacheMode);

            return $this->accessToken;

        } catch (\Exception $e) {

            // Failed to get the access token
            throw $e;

        }

	}

	/**
	 * Get the cached access token
	 *
	 * @param string|null $cacheMode
	 *
	 * @return bool|string
	 */
	public function getCachedToken($cacheMode = null) {

		if($cacheMode == 'session' && !empty($_SESSION['access_token'])) {

			// Get the token stored in session
			return $_SESSION['access_token'];

		}

		// Create your own caching function
		return false;

	}

	/**
	 * Get the cached access token
	 *
	 * @param string $accessToken
	 * @param string|null $cacheMode
	 */
	public function setCachedToken($accessToken, $cacheMode = null) {

		// Create your own caching function
		if($cacheMode == 'session') {

			// Store the token in session
			$_SESSION['access_token'] = $accessToken;

		}

	}

    /**
     * Clear the session
     *
     * @return bool
     */
    public function clearAll() {

        if(isset($_SESSION)) {
            unset($_SESSION['oauth2state']);
            unset($_SESSION['access_token']);
            unset($_SESSION['custom_access_token']);
        }

        // @TODO: Revoke token

        return true;

    }

	/**
	 * Send an authenticated request
	 *
	 * @TODO: Require app secret https://developers.facebook.com/docs/graph-api/securing-requests
	 *
	 * @param string $method
	 * @param string $url
	 * @param array $params
	 *
	 * @return array
	 * @throws \Exception
	 */
	public function authenticatedRequest($method, $url, $params = []) {

		try {

			if(!empty($params['access_token'])) {
				$accessToken = $params['access_token'];
				unset($params['access_token']);
			} else {
				$accessToken = $this->getCachedToken();
			}

			// The provider provides a way to get an authenticated API request for
			// the service, using the access token; it returns an object conforming
			// to Psr\Http\Message\RequestInterface.
			$request = $this->getProvider()->getAuthenticatedRequest(
				$method,
				$url,
				$accessToken,
				$params
			);

			$response = $this->getProvider()->getResponse($request);
			$result = json_decode($response->getBody()->getContents(), true);

			if(!empty($result)) {
				return $result;
			} else {
				$response->getBody()->rewind();
				echo $response->getBody()->getContents();
				return [];
			}

		} catch (ClientException $e) {

			throw $e;

		} catch (ServerException $e) {

			throw $e;

		} catch (IdentityProviderException $e) {

			// Failed to get the access token or user details.
			throw $e;

		}

	}

	/**
	 * Send public request
	 *
	 * @param string $method
	 * @param string $url
	 * @param array $params
	 * @param array $data
	 *
	 * @return array
	 * @throws \Exception
	 */
	public function publicRequest($method, $url, $params = [], $data = []) {

		try {

			$params['app_id'] = $this->clientId;
			if(strpos($url, '?') !== false) {
				$url .= '&' . http_build_query($params);
			} else {
				$url .= '?' . http_build_query($params);
			}

			$request = new Curl($url);
			$request->setMethod($method);
			if(!empty($data)) {
				$request->setPostData($data);
			}

			$response = $request->getResults();

			return Json::toArray($response);


		} catch (\Exception $e) {

			throw $e;

		}

	}

}