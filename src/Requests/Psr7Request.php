<?php
/**
 * This file is part of the Rivera Framework OAuth2 package.
 *
 * (c) Pierre-Julien Mazenot <pj.mazenot@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Rf\OAuth2\Requests;

use GuzzleHttp\Psr7\ServerRequest;
use Rf\Core\Http\Request;

/**
 * Class Psr7Request
 *
 * @package App\Common\Classes\Requests
 */
class Psr7Request extends ServerRequest {

    /**
     * Psr7Request constructor.
     *
     * @param Request $request
     */
    public function __construct(Request $request)
    {

	    // Get the params from the original request
        $method = $request->getMethod();
        $uri = $request->getFullUrl();
        $headers = $request->getHeaders()->toArray();
        $version = '1.1';

	    // Forward the Authorization header
        if(empty($headers['Authorization']) && !empty($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) {
            $headers['Authorization'] = $_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
        }

        parent::__construct($method, $uri, $headers, null, $version);

    }

	/**
	 * @param Request $request
	 *
	 * @return Psr7Request
	 */
    public static function create(Request $request) {

	    // Create the Psr7 request instance
        $psr7Request = new static($request);

	    // Define request body depending on the original request content type
	    $contentType = $request->getContentType();
	    switch ($contentType) {

		    case 'application/json':
		    case 'application/x-www-form-urlencoded':
		    case 'multipart/form-data':
			    $body = (object)$request->getPostData()->toArray();
			    break;

		    default:
		    	$body = (object)[];
			    break;

	    }

	    // Return the Psr7 request with the adapted body
        return $psr7Request->withParsedBody($body);

    }

}