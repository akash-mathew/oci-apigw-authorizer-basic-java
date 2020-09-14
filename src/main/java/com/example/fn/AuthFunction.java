
package com.example.fn;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Base64;
import java.util.Calendar;

public class AuthFunction {

    private static final DateTimeFormatter ISO8601 = DateTimeFormatter.ISO_DATE_TIME;
    private static final String TOKEN_BASIC_PREFIX = "Basic ";

    public static class Input {
        public String type;
        public String token;
    }

    public static class Result {
        // required
        public boolean active = false;
        public String principal;
        public String[] scope;
        public String expiresAt;

        // optional
        public String wwwAuthenticate;

        // optional
        public String clientId;

        // optional context
        public Map<String, Object> context;
    }

    public Result handleRequest(Input input) {
        System.out.println("oci-apigw-authorizer-Basic-java START");
        Result result = new Result();

        if (input.token == null || !input.token.startsWith(TOKEN_BASIC_PREFIX)) {
            result.active = false;
            result.wwwAuthenticate = "Basic error=\"missing_token\"";
            System.out.println("oci-apigw-authorizer-Basic-java END (Token)");
            return result;
        }

        // remove "Basic  " prefix in the token string before processing and get the base64 decoded token string
        String token = input.token.substring(TOKEN_BASIC_PREFIX.length());
		 try
        {
            result = validateToken(token);
        }
        catch (Exception ex)
        {
            result.active = false;
            result.wwwAuthenticate = "Basic error=\"invalid_token\"" ;
        }

        System.out.println("oci-apigw-authorizer-basic-java END");

        return result;
    }
	
	    public Result validateToken(String token)
    {
        Result result = new Result();
        byte[] decodedBytes = Base64.getDecoder().decode(token);
        String decodedString = new String(decodedBytes);
        String[] decodedStringArray = decodedString.split(":");
        String username = decodedStringArray[0];
        String password = decodedStringArray[1];
        if(username.equals("admin") && password.equals("admin"))
        {
            result.active = true;
            result.principal = "dummy";
            result.scope = new String[]{"list:hello", "read:hello", "create:hello", "update:hello", "delete:hello", "someScope"};
            result.expiresAt =  getExpiryDateString();
        }
        else
        {
            result.active = false;
            result.wwwAuthenticate = "Basic error=\"invalid_token\"" ;
        }
        return  result;
    }

    public String getExpiryDateString()
    {
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        Date date = new Date();
        System.out.println("Current Date " + dateFormat.format(date));

        // Convert Date to Calendar
        Calendar c = Calendar.getInstance();
        c.setTime(date);
        c.add(Calendar.DATE, 30);

        // Convert calendar back to Date
        Date currentDatePlusOne = c.getTime();

        return dateFormat.format(currentDatePlusOne);
    }

}