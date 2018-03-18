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

use League\OAuth2\Client\Provider\Facebook;
use League\OAuth2\Client\Token\AccessToken;
use Rf\Core\Http\Curl;
use Rf\Core\Http\Exceptions\CurlException;
use Rf\Core\Utils\Format\Exceptions\JsonDecodeException;
use Rf\Core\Utils\Format\Json;

/**
 * Class OAuth2Facebook
 * 
 * @package Rf\OAuth2
 */
class OAuth2Facebook extends Facebook {

	/**
	 * @param $endpoint
	 * @param array $params
	 * @param AccessToken|string $token
	 *
	 * @return array
	 * @throws CurlException
	 * @throws JsonDecodeException
	 */
	public function call($endpoint, array $params, $token) {

		if(is_a($token, AccessToken::class)) {
			$params['access_token'] = $token->getToken();
		} else {
			$params['access_token'] = $token;
		}
		$params['appsecret_proof'] = hash_hmac('sha256', $params['access_token'], $this->clientSecret);

		$url = self::BASE_GRAPH_URL . $this->graphApiVersion . $endpoint . '?' . http_build_query($params);

		try {

			$request = new Curl($url);
			$request->setMethod('get');

			$response = $request->getResults();

			$data = Json::toArray($response);

			return $data;

		} catch(CurlException $e) {
			throw $e;
		} catch(JsonDecodeException $e) {
			throw $e;
		}

	}

}