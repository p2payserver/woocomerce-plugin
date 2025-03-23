<?php
/*
Plugin Name: FiatPay Server Org Payment Gateway
Description: Redirects to external Node.js payment gateway, handles confirmation, failures, and redirects securely.
Version: 1.1
Author: Your Name
*/

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

// Add gateway to WooCommerce
add_filter( 'woocommerce_payment_gateways', 'fiatpay_add_gateway_class' );
function fiatpay_add_gateway_class( $gateways ) {
    $gateways[] = 'WC_Gateway_FiatPay_Server_Org';
    return $gateways;
}

// Init gateway class
add_action( 'plugins_loaded', 'fiatpay_init_gateway_class' );
function fiatpay_init_gateway_class() {

    class WC_Gateway_FiatPay_Server_Org extends WC_Payment_Gateway {

        public function __construct() {
            $this->id = 'fiatpay_server_org';
            $this->method_title = 'FiatPay Server Org';
            $this->method_description = 'Redirects to external Node.js payment gateway with HMAC verification.';
            $this->has_fields = false;

            $this->init_form_fields();
            $this->init_settings();

            $this->title = $this->get_option( 'title' );
            $this->description = $this->get_option( 'description' );
            $this->node_payment_url = $this->get_option( 'node_payment_url' );
            $this->hmac_secret = $this->get_option( 'hmac_secret' );

            // Save settings
            add_action( 'woocommerce_update_options_payment_gateways_' . $this->id, array( $this, 'process_admin_options' ) );
        }

        public function init_form_fields() {
            $this->form_fields = array(
                'enabled' => array(
                    'title'   => 'Enable/Disable',
                    'type'    => 'checkbox',
                    'label'   => 'Enable FiatPay Server Org Payment Gateway',
                    'default' => 'yes',
                ),
                'title' => array(
                    'title'       => 'Title',
                    'type'        => 'text',
                    'default'     => 'Pay with FiatPay',
                ),
                'description' => array(
                    'title'       => 'Description',
                    'type'        => 'textarea',
                    'default'     => 'Redirect to FiatPay secure server.',
                ),
                'node_payment_url' => array(
                    'title'       => 'Node.js Payment URL',
                    'type'        => 'text',
                    'default'     => 'https://your-node-server.com/pay',
                ),
                'hmac_secret' => array(
                    'title'       => 'HMAC Secret Key',
                    'type'        => 'password',
                    'description' => 'Shared secret key used to sign data.',
                ),
            );
        }

        public function process_payment( $order_id ) {
            $order = wc_get_order( $order_id );

            // Merchant domain
            $domain = parse_url( home_url(), PHP_URL_HOST );

            $data = array(
                'order_id'    => $order_id,
                'amount'      => $order->get_total(),
                'currency'    => $order->get_currency(),
                'email'       => $order->get_billing_email(),
                'merchant'    => $domain,
            );

            // HMAC signature
            $signature = hash_hmac( 'sha256', json_encode( $data ), $this->hmac_secret );
            $data['signature'] = $signature;

            $encoded = base64_encode( json_encode( $data ) );
            $redirect_url = trailingslashit( $this->node_payment_url ) . $encoded;

            wc_reduce_stock_levels( $order_id );

            return array(
                'result'   => 'success',
                'redirect' => $redirect_url,
            );
        }
    }
}

// ----------- REST API Routes -----------

// SUCCESS webhook
add_action( 'rest_api_init', function () {
    register_rest_route( 'fiatpay/v1', '/payment-confirm/', array(
        'methods' => 'POST',
        'callback' => 'fiatpay_handle_payment_confirmation',
        'permission_callback' => '__return_true',
    ));
});

// FAILURE webhook
add_action( 'rest_api_init', function () {
    register_rest_route( 'fiatpay/v1', '/payment-failed/', array(
        'methods' => 'POST',
        'callback' => 'fiatpay_handle_payment_failed',
        'permission_callback' => '__return_true',
    ));
});

// Payment Success Handler
function fiatpay_handle_payment_confirmation( WP_REST_Request $request ) {
    return fiatpay_process_result( $request, 'success' );
}

// Payment Failure Handler
function fiatpay_handle_payment_failed( WP_REST_Request $request ) {
    return fiatpay_process_result( $request, 'failed' );
}

// Common Processing Logic
function fiatpay_process_result( $request, $status ) {
    $params = $request->get_json_params();

    if ( empty( $params['order_id'] ) || empty( $params['signature'] ) ) {
        return new WP_Error( 'invalid_request', 'Missing parameters', array( 'status' => 400 ) );
    }

    $order_id = intval( $params['order_id'] );
    $order = wc_get_order( $order_id );

    if ( ! $order ) {
        return new WP_Error( 'invalid_order', 'Order not found', array( 'status' => 404 ) );
    }

    // Get plugin settings
    $gateways = WC()->payment_gateways->payment_gateways();
    $gateway  = $gateways['fiatpay_server_org'];
    $secret   = $gateway->get_option( 'hmac_secret' );

    // Recalculate signature
    $expected_data = array(
        'order_id' => $order_id,
        'amount'   => $order->get_total(),
        'currency' => $order->get_currency(),
        'email'    => $order->get_billing_email(),
        'merchant' => parse_url( home_url(), PHP_URL_HOST ),
    );

    $expected_signature = hash_hmac( 'sha256', json_encode( $expected_data ), $secret );

    if ( $params['signature'] !== $expected_signature ) {
        return new WP_Error( 'invalid_signature', 'Signature mismatch', array( 'status' => 403 ) );
    }

    if ( $status === 'success' ) {
        $order->payment_complete();
        $order->add_order_note( 'Payment confirmed via FiatPay.' );
        // Redirect to success page
        wp_redirect( home_url( '/fiatpay-success/' ) );
        exit;
    } else {
        $reason = isset( $params['reason'] ) ? sanitize_text_field( $params['reason'] ) : 'Unknown';
        $order->update_status( 'failed', 'Payment failed: ' . $reason );
        // Redirect to failure page
        wp_redirect( home_url( '/fiatpay-failed/' ) );
        exit;
    }
}

// ----------- Success & Failure Pages -----------

add_action( 'init', function() {
    // Success Page
    add_rewrite_rule( '^fiatpay-success/?$', 'index.php?fiatpay_success=1', 'top' );
    // Failure Page
    add_rewrite_rule( '^fiatpay-failed/?$', 'index.php?fiatpay_failed=1', 'top' );
    flush_rewrite_rules( false );
});

add_filter( 'query_vars', function( $vars ) {
    $vars[] = 'fiatpay_success';
    $vars[] = 'fiatpay_failed';
    return $vars;
});

add_action( 'template_redirect', function() {
    if ( get_query_var( 'fiatpay_success' ) ) {
        fiatpay_render_page( 'Payment Successful', 'Your payment was successful!' );
        exit;
    }
    if ( get_query_var( 'fiatpay_failed' ) ) {
        fiatpay_render_page( 'Payment Failed', 'Unfortunately, your payment failed.' );
        exit;
    }
});

// Page Renderer
function fiatpay_render_page( $title, $message ) {
    get_header();
    echo '<div style="text-align: center; margin: 50px;">';
    echo '<h1>' . esc_html( $title ) . '</h1>';
    echo '<p>' . esc_html( $message ) . '</p>';
    echo '<a href="' . esc_url( wc_get_cart_url() ) . '" style="padding: 10px 20px; background: #0071a1; color: #fff; text-decoration: none; display: inline-block; margin-top: 20px;">Return to Cart</a>';
    echo '</div>';
    get_footer();
}
