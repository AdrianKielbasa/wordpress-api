<?php

// Require Authentication for All Requests
add_filter('rest_authentication_errors', function($result) {
    // If a previous authentication check was applied,
    // pass that result along without modification.
    if (true === $result || is_wp_error($result)) {
        return $result;
    }

    $requestUri = $_SERVER['REQUEST_URI'];

    // No authentication has been performed yet.
    // Return an error if user is not logged in.
    if (
        !is_user_logged_in() &&
        stripos($requestUri, '/jwt-auth/v1/token/validate') === false
    ) {
        return new WP_Error(
            'rest_not_logged_in',
            __('You are not currently logged in.'),
            ['status' => 401]
        );
    }

    // Our custom authentication check should have no effect
    // on logged-in requests
    return $result;
});

/**
 * Change the token's expire value.
 *
 * @param int $expire The default "exp" value in timestamp.
 * @param int $issuedAt The "iat" value in timestamp.
 *
 * @return int The "nbf" value.
 */
add_filter(
    'jwt_auth_expire',
    function ($expire, $issuedAt) {
        // Modify the "expire" here.
        return time() + (MINUTE_IN_SECONDS * 10);
    },
    10,
    2
);