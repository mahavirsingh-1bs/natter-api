package com.manning.apisecurityinaction;

import static spark.Spark.after;
import static spark.Spark.afterAfter;
import static spark.Spark.before;
import static spark.Spark.delete;
import static spark.Spark.exception;
import static spark.Spark.get;
import static spark.Spark.halt;
import static spark.Spark.internalServerError;
import static spark.Spark.notFound;
import static spark.Spark.port;
import static spark.Spark.post;
import static spark.Spark.secure;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Set;

import org.dalesbred.Database;
import org.dalesbred.result.EmptyResultException;
import org.h2.jdbcx.JdbcConnectionPool;
import org.json.JSONException;
import org.json.JSONObject;

import com.google.common.util.concurrent.RateLimiter;
import com.manning.apisecurityinaction.controller.AuditController;
import com.manning.apisecurityinaction.controller.DroolsAccessController;
import com.manning.apisecurityinaction.controller.ModeratorController;
import com.manning.apisecurityinaction.controller.SpaceController;
import com.manning.apisecurityinaction.controller.TokenController;
import com.manning.apisecurityinaction.controller.UserController;
import com.manning.apisecurityinaction.token.OAuth2TokenStore;
import com.manning.apisecurityinaction.token.SecureTokenStore;

import spark.Request;
import spark.Response;
import spark.Spark;

public class Main {

	private static String clientId = "test";
	private static String clientSecret = "password";
	
	public static void main(String... args) throws Exception {
		secure("localhost.p12", "changeit", null, null);
		port(args.length > 0 ? Integer.parseInt(args[0]) 
				: spark.Service.SPARK_DEFAULT_PORT);
		Spark.staticFiles.location("/public");
		
		var rateLimiter = RateLimiter.create(2.0d);
		before((request, response) -> {
			if (!rateLimiter.tryAcquire()) {
				response.header("Retry-After", "2");
				halt(429);
			}
		});
		before(new CorsFilter(Set.of("https://localhost:9999")));
		
		before(((request, response) -> {
            if (request.requestMethod().equals("POST") &&
            !"application/json".equals(request.contentType())) {
                halt(415, new JSONObject().put(
                    "error", "Only application/json supported"
                ).toString());
            }
        }));
		
		var datasource = JdbcConnectionPool.create("jdbc:h2:mem:natter", "natter", "password");
		var database = Database.forDataSource(datasource);
		createTables(database);
		
		datasource = JdbcConnectionPool.create("jdbc:h2:mem:natter", "natter_api_user", "password");
		database = Database.forDataSource(datasource);
		
		var spaceController = new SpaceController(database);
		var userController = new UserController(database);
		
		/**
		var keyPassword = System.getProperty("keystore.password", "changeit").toCharArray();
        var keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new FileInputStream("keystore.p12"), keyPassword);
        var encKey = keyStore.getKey("aes-key", keyPassword);
        */
        
        var introspectionEndpoint =
        	     URI.create("https://as.example.com:8443/oauth2/introspect");
        	SecureTokenStore tokenStore = new OAuth2TokenStore(
        	     introspectionEndpoint, clientId, clientSecret);
        var tokenController = new TokenController(tokenStore);
		
		before(userController::authenticate);
		before(tokenController::validateToken);
		
		var auditController = new AuditController(database);
		before(auditController::auditRequestStart);
		
		var droolsController = new DroolsAccessController();
        before("/*", droolsController::enforcePolicy);
		
		before("/sessions", userController::requireAuthentication);
		before("/sessions", 
				tokenController.requireScope("POST", "full_access"));
		post("/sessions", tokenController::login);
		delete("/sessions", tokenController::logout);
		
		before("/spaces", userController::requireAuthentication);
		before("/sessions", 
				tokenController.requireScope("POST", "create_scope"));
		post("/spaces", spaceController::createSpace);
		
		before("/spaces/:spaceId/messages", userController::lookupPermissions);
        before("/spaces/:spaceId/messages/*", userController::lookupPermissions);
        before("/spaces/:spaceId/members", userController::lookupPermissions);
		
		before("/spaces/*/messages", 
				tokenController.requireScope("POST", "post_message"));
		before("/spaces/:spaceId/messages", 
				userController.requirePermission("POST", "w"));
		post("/spaces/:spaceId/messages", spaceController::postMessage);
			 
		before("/spaces/*/messages/*", 
				tokenController.requireScope("POST", "read_message"));
		before("/spaces/:spaceId/messages/*", 
				userController.requirePermission("GET", "r"));
		get("/spaces/:spaceId/messages/:msgId", spaceController::readMessage);
			 
		before("/spaces/*/messages", 
				tokenController.requireScope("POST", "list_messages"));
		before("/spaces/:spaceId/messages", userController.requirePermission("GET", "r"));
		get("/spaces/:spaceId/messages", spaceController::findMessages);

		before("/spaces/*/members", 
				tokenController.requireScope("POST", "add_member"));
		before("/spaces/:spaceId/members", userController.requirePermission("POST", "rwd"));
		post("/spaces/:spaceId/members", spaceController::addMember);
		
		
		var moderatorController = new ModeratorController(database);
		before("/spaces/*/members", 
				tokenController.requireScope("DELETE", "delete_message"));
		before("/spaces/:spaceId/messages/*", userController.requirePermission("DELETE", "d"));
		delete("/spaces/:spaceId/messages/:msgId", moderatorController::deletePost);
		
		post("/users", userController::registerUser);
		get("/logs", auditController::readAuditLog);
		
		after((request, response) -> {
			response.type("application/json");
		});
		
		exception(IllegalArgumentException.class, Main::badRequest);
		exception(JSONException.class, Main::badRequest);
		exception(EmptyResultException.class, 
				(e, request, response) -> response.status(404));
		
		internalServerError(new JSONObject()
			.put("error", "internal server error").toString());
		notFound(new JSONObject()
			.put("error", "not found").toString());
		
		after(auditController::auditRequestEnd);
		afterAfter((request, response) -> {
			response.type("application/json;charset=utf-8");
			response.header("X-Content-Type-Options", "nosniff");
			response.header("X-Frame-Options", "DENY");
			response.header("X-XSS-Protection", "0");
			response.header("Cache-Control", "no-store");
			response.header("Content-Security-Policy",
                    "default-src 'none'; frame-ancestors 'none'; sandbox");
			response.header("Strict-Transport-Security", "max-age=3");
			response.header("Server", "");
		});
	}

	private static void badRequest(Exception ex, Request request, Response response) {
		response.status(400);
		response.body(new JSONObject()
				.put("error", ex.getMessage()).toString());
	}
	
	private static void createTables(Database database) throws Exception {
		var path = Paths.get(Main.class.getResource("/schema.sql").toURI());
		database.update(Files.readString(path));
	}

}
