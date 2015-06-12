/**
 * 
 */
package com.pasm;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import org.json.JSONObject;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeRequestUrl;
import com.google.api.client.googleapis.auth.oauth2.GoogleTokenResponse;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson.JacksonFactory;

/**
 * @author Peter
 * 
 */
@Controller
public class GoogleController {

	private static final Iterable<String> SCOPE = Arrays
			.asList("https://www.googleapis.com/auth/userinfo.profile;https://www.googleapis.com/auth/userinfo.email"
					.split(";"));
	private static final String USER_INFO_URL = "https://www.googleapis.com/oauth2/v1/userinfo";
	private static final JsonFactory JSON_FACTORY = new JacksonFactory();
	private static final HttpTransport HTTP_TRANSPORT = new NetHttpTransport();
	// end google authentication constants

	private String stateToken;

	private final GoogleAuthorizationCodeFlow flow;
	//google client id
	private static final String CLIENT_ID = "*****";
	//google secret code
	private static final String CLIENT_SECRET = "******";
	private static final String CALLBACK_URI = "http://localhost:8080/GoogleOuthExample/authSuccess";

	public GoogleController() {
		flow = new GoogleAuthorizationCodeFlow.Builder(HTTP_TRANSPORT,
				JSON_FACTORY, CLIENT_ID, CLIENT_SECRET, (Collection<String>) SCOPE).build();
		generateStateToken();
	}

	private void generateStateToken() {
		SecureRandom sr1 = new SecureRandom();
		stateToken = "google;" + sr1.nextInt();
	}

	
	 /**
	   * This method is used to redirect to google api.
	   * 
	   * @return String 
	   */
	@RequestMapping(value = "/googleLogin", method = RequestMethod.GET)
	public String buildLoginUrl(Map<String, Object> model,
			HttpServletRequest request) {
		final GoogleAuthorizationCodeRequestUrl url = flow
				.newAuthorizationUrl();
		return "redirect:"
				+ url.setRedirectUri(CALLBACK_URI).setState(stateToken).build();
	}
	
	 /**
	   * This method is used display the user information.
	   * This method is calling after authentication success
	   * @return String 
	   */
	@RequestMapping(value = "/authSuccess")
	public String getRedirectURL(Map<String, Object> model,final HttpServletRequest request)
			throws Exception {
		final String authCode =request.getParameter("code");
		final GoogleTokenResponse response = flow.newTokenRequest(authCode).setRedirectUri(CALLBACK_URI).execute();
		final Credential credential = flow.createAndStoreCredential(response, null);
		final HttpRequestFactory requestFactory = HTTP_TRANSPORT.createRequestFactory(credential);
		// Make an authenticated request
		final GenericUrl url = new GenericUrl(USER_INFO_URL);
		final HttpRequest request1 = requestFactory.buildGetRequest(url);
		request1.getHeaders().setContentType("application/json");
		final String jsonIdentity = request1.execute().parseAsString();
		//Converting into json object
		JSONObject jsonObj = new JSONObject(jsonIdentity);
		
		model.put("firstName", jsonObj.get("given_name"));
		model.put("lastName", jsonObj.get("family_name"));
		model.put("email", jsonObj.get("email"));
		model.put("gender", jsonObj.get("gender"));
		return "googleUserInfo";

	}

}
