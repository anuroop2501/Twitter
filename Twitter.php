<?php
class Twitter
{
    private $oauth_access_token;   // variable to store access token given by twitter
    private $oauth_access_token_secret; // variable to store access token secret given by twitter
    private $consumer_key;
    private $consumer_secret;
    private $postfields;
    private $getfield;         //to store the search hashtag
    protected $oauth;          //to store the oauth keys like consumer keys etc
    public $url;
    public $requestMethod;     // either get or post

  // constructor which intializes the authentication values
    public function __construct(array $settings)
    {
        if (!in_array('curl', get_loaded_extensions()))
        {
            throw new Exception('Please install cURL');
        }

        if (!isset($settings['oauth_access_token'])
            || !isset($settings['oauth_access_token_secret'])
            || !isset($settings['consumer_key'])
            || !isset($settings['consumer_secret']))
        {
            throw new Exception('Pass the correct parameters');
        }

        $this->oauth_access_token = $settings['oauth_access_token'];
        $this->oauth_access_token_secret = $settings['oauth_access_token_secret'];
        $this->consumer_key = $settings['consumer_key'];
        $this->consumer_secret = $settings['consumer_secret'];
    }

    public function setGetfield($string)
    {
        if (!is_null($this->getPostfields()))
        {
            throw new Exception('You can only choose get OR post fields.');
        }

        $getfields = preg_replace('/^\?/', '', explode('&', $string)); //explode will splits the strings when it come across '&'
        $params = array();

        foreach ($getfields as $field)
        {
            if ($field !== '')
            {
                list($key, $value) = explode('=', $field);
                $params[$key] = $value;
            }
        }

        $this->getfield = '?' . http_build_query($params);

        return $this;
    }
   public function getGetfield()
    {
        return $this->getfield;
    }
   public function getPostfields()
    {
        return $this->postfields;
    }
   public function buildOauth($url, $requestMethod)
    {
        if (!in_array(strtolower($requestMethod), array('post', 'get')))
        {
            throw new Exception('Request method must be either POST or GET');
        }

        $consumer_key              = $this->consumer_key;
        $consumer_secret           = $this->consumer_secret;
        $oauth_access_token        = $this->oauth_access_token;
        $oauth_access_token_secret = $this->oauth_access_token_secret;

        $oauth = array(
            'oauth_consumer_key' => $consumer_key,
            'oauth_nonce' => time(),
            'oauth_signature_method' => 'HMAC-SHA1',
            'oauth_token' => $oauth_access_token,
            'oauth_timestamp' => time(),
            'oauth_version' => '1.0'
        );

        $getfield = $this->getGetfield();

        if (!is_null($getfield))
        {
            $getfields = str_replace('?', '', explode('&', $getfield));

            foreach ($getfields as $g)
            {
                $split = explode('=', $g);
                if (isset($split[1]))
                {
                    $oauth[$split[0]] = urldecode($split[1]);
                }
            }
        }

        $postfields = $this->getPostfields();

        if (!is_null($postfields)) {
            foreach ($postfields as $key => $value) {
                $oauth[$key] = $value;
            }
        }

        $base_info = $this->buildBaseString($url, $requestMethod, $oauth);
        $composite_key = rawurlencode($consumer_secret) . '&' . rawurlencode($oauth_access_token_secret);
        $oauth_signature = base64_encode(hash_hmac('sha1', $base_info, $composite_key, true));
        $oauth['oauth_signature'] = $oauth_signature;

        $this->url = $url;
        $this->requestMethod = $requestMethod;
        $this->oauth = $oauth;

        return $this;
    }
    // to perform the request asked for ,used cURL for communication
    public function performRequest($return = true, $curlOptions = array())
    {
        if (!is_bool($return))
        {
            throw new Exception('performRequest parameter must be true or false');
        }
        $header =  array($this->buildAuthorizationHeader($this->oauth), 'Expect:');

        $getfield = $this->getGetfield();
        $postfields = $this->getPostfields();
        $feed = curl_init();
        curl_setopt ($feed, CURLOPT_CAINFO, "C:\Users\ANUROOP\Desktop\cacert.pem");//so as to satisfy the SSL request
        $options = array(
            CURLOPT_HTTPHEADER => $header,
            CURLOPT_HEADER => false,
            CURLOPT_URL => $this->url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 10,
        ) + $curlOptions;

        if (!is_null($postfields))
        {
            $options[CURLOPT_POSTFIELDS] = http_build_query($postfields);
        }
        else
        {
            if ($getfield !== '')
            {
                $options[CURLOPT_URL] .= $getfield;
            }
        }
        curl_setopt_array($feed, $options);
        $json = curl_exec($feed);

        if (($error = curl_error($feed)) !== '')
        {
            curl_close($feed);

          throw new \Exception($error);
        }

        curl_close($feed);

        return $json;
    }

    // this function is to build the base url
    private function buildBaseString($baseURI, $method, $params)
    {
        $return = array();
        ksort($params);

        foreach($params as $key => $value)
        {
            $return[] = rawurlencode($key) . '=' . rawurlencode($value);
        }

        return $method . "&" . rawurlencode($baseURI) . '&' . rawurlencode(implode('&', $return));
    }
    // to build header
    private function buildAuthorizationHeader(array $oauth)
    {
        $return = 'Authorization: OAuth ';
        $values = array();

        foreach($oauth as $key => $value)
        {
            if (in_array($key, array('oauth_consumer_key', 'oauth_nonce', 'oauth_signature',
                'oauth_signature_method', 'oauth_timestamp', 'oauth_token', 'oauth_version'))) {
                $values[] = "$key=\"" . rawurlencode($value) . "\"";
            }
        }

        $return .= implode(', ', $values);
        return $return;
    }

    public function request($url, $method = 'get', $data = null, $curlOptions = array())
    {
        if (strtolower($method) === 'get')
        {
            $this->setGetfield($data);
        }
        else
        {
            $this->setPostfields($data);
        }

        return $this->buildOauth($url, $method)->performRequest(true, $curlOptions);
    }
}

