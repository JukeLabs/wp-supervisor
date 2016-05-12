<?php
/**
 * WP Supervisor
 *
 * Add WP actions to a custom log and block unwanted traffic.
 *
 * @package   WP_Supervisor
 * @author    Juke Labs, Inc. <hello@jukelabs.com>
 * @license   GPL-2.0+
 * @copyright 2016 Juke Labs, Inc.
 *
 * @wordpress-plugin
 * Plugin Name:       WP Supervisor
 * Plugin URI:
 * Description:       Add WP actions to a custom log and block unwanted traffic.
 * Version:           1.0.0
 * Author:            Juke Labs, Inc.
 * Author URI:        http://jukelabs.com
 * License:           GPL-2.0+
 * License URI:       http://www.gnu.org/licenses/gpl-2.0.txt
 * GitHub Plugin URI:
 */

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
	die;
}

/**
 * WP Supervisor Class
 */
class WP_Supervisor {

	// DEFAULTS
	// *****************

	private $log_file_dir = WP_CONTENT_DIR;
	private $log_file_name = 'supervisor.log';

	private $severities = array(
		0 => 'debug',
		1 => 'notice',
		2 => 'info',
		3 => 'warning',
		4 => 'error',
		5 => 'critical'
	);

	// SINGLETON & CONSTRUCTOR
	// *****************

	private static $instance = null;

	public static function get_instance() {
		if (null == self::$instance) {
			self::$instance = new self;
		}
		return self::$instance;
	}

	/**
	 * Class constructor
	 */
	function __construct() {
		$this->defineVars();
		$this->createLog();
		$this->init();
	}

	// FUNCTIONS
	// *****************

	/**
	 * init
	 * @return void
	 */
	private function init() {

		//-------------------------------------------------
		// User Authentication
		//-------------------------------------------------

		/**
		 * wp_login
		 * Log successful user authentication
		 * @since 1.0.0
		 * @return void
		 */
		add_action( 'wp_login',
			function($user_login, $user)
			{
				$msg = "Authentication accepted password for $user_login from " . $this->getRemoteAddress();
				$this->log( $msg, 'auth', 2 );

				return $user_login;
			},10,2);

		/**
		 * wp_login_failed
		 * Log unsuccessful user authentication and if user is not registered then force a 403 error
		 * @since 1.0.0
		 * @return void
		 */
		add_action( 'wp_login_failed',
			function($user_login)
			{
				$msg = ( $valid_user = wp_cache_get($user_login, 'userlogins') )
					? "Authentication failure for {$user_login} from " . $this->getRemoteAddress()
					: "Authentication attempt for unknown user {$user_login} from " . $this->getRemoteAddress();
				$this->log( $msg, 'auth', ($valid_user ? 2 : 3 ) );

				if( !$valid_user ) {
					$this->returnForbidden();
				}

				return $user_login;
			});

		/**
		 * redirect_canonical
		 * Block user enumeration attempts
		 * @since 1.0.0
		 * @return void
		 */
		add_filter( 'redirect_canonical',
			function($redirect_url, $requested_url)
			{
				if (intval(@$_GET['author'])) {

					$msg = "Blocked user enumeration attempt from " . $this->getRemoteAddress();
					$this->log( $msg, 'auth', 3 );
					$this->returnForbidden();
				}

				return $redirect_url;
			},10,2);

		//-------------------------------------------------
		// XML RPC
		//-------------------------------------------------

		/**
		 * xmlrpc_call
		 * Log pingback calls
		 * @since 1.0.0
		 * @return void
		 */
		add_action( 'xmlrpc_call',
			function($call)
			{
				if ('pingback.ping' == $call) {
					$msg = "Pingback requested from " . $this->getRemoteAddress();
					$this->log( $msg, 'xmlrpc', 2 );
				}
			});

		/**
		 * xmlrpc_login_error
		 * Log xmlrpc login errors
		 * @since 1.0.0
		 * @return void
		 */
		add_action( 'xmlrpc_login_error',
			function($error, $user)
			{
				$msg = "XML-RPC authentication failure from " . $this->getRemoteAddress();
				$this->log( $msg, 'xmlrpc', 3 );
				$this->returnForbidden();
			},10,2);

		/**
		 * xmlrpc_pingback_error
		 * Log xmlrpc pingback errors
		 * @since 1.0.0
		 * @return void
		 */
		add_filter( 'xmlrpc_pingback_error',
			function($ixr_error)
			{
				if (48 === $ixr_error->code) {
					return $ixr_error;
				}

				$msg = "Pingback error {$ixr_error->code} generated from " . $this->getRemoteAddress();
				$this->log( $msg, 'xmlrpc', 3 );
			},5);

		/**
		 * xmlrpc_methods
		 * Update xmlrpc methods
		 * @since 1.0.0
		 * @return void
		 */
		add_filter( 'xmlrpc_methods',
			function( $methods )
			{
			   unset( $methods['pingback.ping'] );
			   return $methods;
			});

		//-------------------------------------------------
		// Plugin Activity
		//-------------------------------------------------

		/**
		 * activated_plugin
		 * Log plugin activation
		 * @since 1.0.0
		 * @return void
		 */
		add_action( 'activated_plugin',
			function($plugin)
			{
				$user = wp_get_current_user();
				$user_login = $user->user_login;
				$msg = "Activated plugin {$plugin} by {$user_login} from " . $this->getRemoteAddress();
				$this->log( $msg, 'plugin', 2 );
			},50);

		/**
		 * deactivated_plugin
		 * Log plugin deactivation
		 * @since 1.0.0
		 * @return void
		 */
		add_action( 'deactivated_plugin',
			function($plugin)
			{
				$user = wp_get_current_user();
				$user_login = $user->user_login;
				$msg = "Deactivated plugin {$plugin} by {$user_login} from " . $this->getRemoteAddress();
				$this->log( $msg, 'plugin', 2 );
			},50);

		//-------------------------------------------------
		// Post/Page Activity
		//-------------------------------------------------

		/*
		 * @since 1.0.0
		 */
		add_action( 'publish_post',
			function($post_id, $post)
			{
				$user = wp_get_current_user();
				$user_login = $user->user_login;
				$msg = "Published post #{$post_id} by user {$user_login} from " . $this->getRemoteAddress();
				$this->log( $msg, 'post', 2 );

			},50,2);

		/*
		 * @since 1.0.0
		 */
		add_action( 'delete_post',
			function($post_id)
			{
				$user = wp_get_current_user();
				$user_login = $user->user_login;
				$msg = "Deleted post #{$post_id} by user {$user_login} from " . $this->getRemoteAddress();
				$this->log( $msg, 'post', 2 );

			},50);

		//-------------------------------------------------
		// Media Library Activity
		//-------------------------------------------------

		//-------------------------------------------------
		// Comment Activity
		//-------------------------------------------------
	}

	/**
	 * defineVars
	 * @return void
	 */
	private function defineVars() {

		// Set log enabled
		$this->logEnabled = false;
		if( ( defined('SUPERVISOR_LOG_ENABLED') ) && SUPERVISOR_LOG_ENABLED ) {
			$this->logEnabled = true;
 		}

 		if( $this->logEnabled ) {

 			// Define log directory
			$this->logFileDir = $this->log_file_dir;
			if( defined('SUPERVISOR_LOG_DIR') && SUPERVISOR_LOG_DIR !== '' ) {
				$this->logFileDir = constant('SUPERVISOR_LOG_DIR');
			}

			// Define log file name
			$this->logFileName = $this->log_file_name;
			if( defined('SUPERVISOR_LOG_NAME') && SUPERVISOR_LOG_NAME !== '' ) {
				$this->logFileName = constant('SUPERVISOR_LOG_NAME');
			}

			// Define log full path
			$this->logFilePath =  $this->logFileDir . '/' . $this->logFileName;
 		}
	}

	/**
	 * createLog
	 * @return void
	 */
	private function createLog() {

		if( !$this->logEnabled ) return;

		// Create log directory
		if( !file_exists($this->logFileDir) ) {
			if( !@mkdir( $this->logFileDir, 0755, true ) ) {

				// abort
				$this->logEnabled = false;
				@error_log( "WP_Supervisor: createLog():  Unable to create 'custom log' directory '{$this->logFileDir}'" );
				return;
			};
		}

		// Create log file
		if( !file_exists($this->logFilePath) ) {
			if( !@touch($this->logFilePath) ) {

				// abort
				$this->logEnabled = false;
				@error_log( "WP_Supervisor: createLog():  Unable to create 'custom log' file '{$this->logFilePath}'" );
				return;
			};

			@chmod($this->logFilePath, 0644);
		}
	}

	/**
	 * log
	 * @return void
	 */
	public function log( $log, $type="log", $severity=2 ) {

		if( !$this->logEnabled ) return;

		// Define timestamp
		$timestamp = date('M d H:i:s', time());

		// Define hostname
		$hostname = strtolower(php_uname('n'));

		// Define severity
		$severity = $this->getSeverity($severity);

		// Define tag
		$tag = 'wordpress';

		// Define host
		$host = $_SERVER['HTTP_HOST'];

		// How we handle array and objects
		if ( is_array( $log ) || is_object( $log ) ) {
			$log = print_r( $log, true );
		}

		// Add formatting and timestamp
		// $log = "{$timestamp} {$hostname} {$tag}({$host})[{$type}][{$severity}]: " . $log . PHP_EOL;
		$log = "{$timestamp} {$hostname} {$tag}({$host}): " . $log . PHP_EOL;

		// Write log
		if( !@error_log($log, 3, $this->logFilePath) ) {
			// abort
			@error_log( "WP_Supervisor: log():  Unable to write to log file '{$this->logFilePath}'" );
			return;
		}
	}

	/**
	 * getRemoteAddress
	 * @return void
	 */
	private function getRemoteAddress() {
		return $_SERVER['REMOTE_ADDR'];
	}

	/**
	 * getSeverity
	 * @return void
	 */
	private function getSeverity( $severity=0 ) {

		// Fix to a integer
		$severity = (int) $severity;

		// Return severity
		if( $this->severities[$severity] ) {
			return $this->severities[$severity];
		} else {
			return $this->severities[0];
		}
	}

	/**
	 * returnForbidden
	 * @return void
	 */
	private function returnForbidden() {
		if (ob_get_contents()) {
			ob_end_clean();
		}
		wp_die( __( 'You do not have permission to access this page.' ), 403 );
		exit;
	}
}

// Global accessor function to singleton
function supervisor() {
	return WP_Supervisor::get_instance();
}
supervisor();