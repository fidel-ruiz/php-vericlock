<?php

namespace fidelruiz\VeriClock;

use GuzzleHttp\Client;
use GuzzleHttp\Command\Guzzle\Description;
use GuzzleHttp\Command\Guzzle\GuzzleClient;
use GuzzleHttp\HandlerStack;
use Psr\Http\Message\RequestInterface;

class VeriClockClient extends GuzzleClient
{

    public static function create($config = [])
    {
        $handler_stack = HandlerStack::create();
        // Add a signature handler to the stack.
        $handler_stack->push(function (callable $handler) use ($config) {
            return function (RequestInterface $request, array $options) use ($handler, $config) {
                // Return the request body signature
                return $handler(
                    $request->withAddedHeader(
                        'vericlock_signature',
                        VeriClockClient::_generateSignature($request->getUri(), $config['private_key'], $request->getBody())
                    ),
                    $options
                );
            };
        }, 'sig');

        // Add an authentication handler to the stack.
        $handler_stack->push(function (callable $handler) use ($config) {
            return function (RequestInterface $request, array $options) use ($handler, $config) {
                // Return the request with a Bearer authorization header.
                return $handler(
                    $request->withAddedHeader('Authorization', 'Bearer '+$config['vericlock_authtoken']),
                    $options
                );
            };
        }, 'auth');

        // Load the service description file.
        $service_description = new Description(
            ['baseUrl' => $config['base_uri']] + (array) json_decode(file_get_contents(__DIR__ . '/../service.json'), true)
        );

        // Creates the client and sets the default request headers.
        $client = new Client([
            'headers' => [
                'Content-Type' => 'application/json',
                'Accept' => 'application/json',
                'vericlock_api_public_key' => $config['vericlock_api_public_key'],
                'vericlock_domain' => $config['vericlock_domain'],
            ],
        ]);

        return new static($client, $service_description, null, null, null, $config);
    }

    private static function _generateSignature($uri, $privateKey, $bodyStr)
    {
        $hashStr = $uri . $bodyStr;
        $sig = hash_hmac('sha256', $hashStr, $privateKey);
        return $sig;
    }
}
