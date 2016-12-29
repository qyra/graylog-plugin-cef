package org.graylog.plugins.cef.parser;

import autovalue.shaded.com.google.common.common.collect.ImmutableMap;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.ArrayList;

public class CEFParser {
    private static final DateTimeFormatter TIMESTAMP_PATTERN = DateTimeFormat.forPattern("MMM dd HH:mm:ss");

    private static final CEFFieldsParser FIELDS_PARSER = new CEFFieldsParser();

    private final DateTimeZone timezone;

    public CEFParser(DateTimeZone timezone) {
        this.timezone = timezone;
    }

    /*
     * The first 7 unescaped pipes must split the message into parts.
     * Pipes can be escaped with \
     * After that, pipes no longer split, because they are regular chars in the extension field.
     * This function returns null when an invalid escape is created.
     * This should return an arraylist of length 8 for all valid CEF input.
     */ 
    public static ArrayList<String> pipeSplit(String in){
        /*
         * An example of what the input looks like, and what indices correspond to what field in the output.
         * Here is a line with the syslog header - numbers on top are array indexes
         * 0                          1                2          3      4    5                                           6  7
         * <132>Aug 14 14:26:55 CEF:0|Trend Micro Inc.|OSSEC HIDS|v2.8.3|2502|User missed the password more than one time|10|dvc=ip-172-30-2-212 cs2=ip-172-30-2-212->/var/log/auth.log cs2Label=Location cfp2=90.01 cfp2Label=SomeFloat spt=22
         * 
         * Here is a line with just the CEF data (As created by arcsite, etc)
         * 0     1                2          3      4    5                                           6  7
         * CEF:0|Trend Micro Inc.|OSSEC HIDS|v2.8.3|2502|User missed the password more than one time|10|dvc=ip-172-30-2-212 cfp2=90.01 cfp2Label=SomeFloat spt=22 cs2=ip-172-30-2-212->/var/log/auth.log cs2Label=Location msg=Aug 14 14:26:53 ip-172-30-2-212 sshd[16217]: PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=116.31.116.17  user=root
         * 
         */
        
        int token_number = 1;
        boolean escaped = false;
        
        ArrayList<String> tokens = new ArrayList<String>();
        StringBuilder curr = new StringBuilder();
        
        for (int i = 0; i < in.length(); i++){
            char c = in.charAt(i);
            
            if (token_number <= 7){
                if (escaped){
                    escaped = false;
                    //This must be an escapable char
                    
                    switch (c){
                    case '\\':
                        curr.append('\\');
                        break;
                    case '|':
                        curr.append('|');
                        break;
                    default:
                        //Found a character which should not be escaped.
                        return null;
                    }
                    
                } else {
                    switch (c){
                    case '\\':
                        escaped = true;
                        break;
                    case '|':
                        tokens.add(curr.toString());
                        token_number++;
                        curr = new StringBuilder();
                        break;
                    default:
                        curr.append(c);
                    }
                }
            } else {
                //After the 7th |, we don't care what the chars are. 
                //Append them all and let the field parser handle the rest.
                curr.append(c);
            }
        }
        String extStr = curr.toString();
        tokens.add(extStr);
        
        return tokens;
    }

    public int parseSeverity(String severity_string){
        int retVal = 0;
        try {
            retVal = Integer.valueOf(severity_string);
            if (retVal < -1 || retVal > 10){
                throw new IllegalArgumentException(severity_string + " is not a valid severity (should be in 0..10)");
            }
            
        } catch (NumberFormatException e) {
            //Conver to lowercase, remove whitespace
            String lowered = severity_string.toLowerCase();
            if (lowered.equals("low")){
                retVal = 3;
            } else if (lowered.equals("med") || lowered.equals("medium")){
                retVal = 6;
            } else if (lowered.equals("high")){
                retVal = 8;
            } else if (lowered.equals("very high") || lowered.equals("very-high")){
                retVal = 10;
            } else if (lowered.equals("unknown")){
                retVal = -1;
            } else {
                throw new IllegalArgumentException(severity_string + " is not a valid string or numeric severity - " + e.getMessage());
            }
        }
        return retVal;
    }

    private static final Pattern HEADER_REGEX = Pattern.compile("(?:^<\\d+>([a-zA-Z]{3}\\s+\\d{1,2} \\d{1,2}:\\d{1,2}:\\d{1,2}).*|^)CEF:(\\d+?)", Pattern.DOTALL);
    private static final Pattern EXTENSION_REGEX =Pattern.compile("(.+?)(?:$| (msg=.+))", Pattern.DOTALL);
    
    public CEFMessage parse(String x) throws ParserException {
        ArrayList<String> tokens = pipeSplit(x);
        //Verify that there are 8 pipe delimited fields total.
        int token_count = tokens.size();
        if (token_count >= 9){
            throw new ParserException("There is a bug in the pipeSplit function. Found too many fields, this should never happen");
        } else if (token_count <= 7){
            throw new ParserException("This message was not recognized as CEF and could not be parsed. 8 pipe-seperated sections should be present");
        }

        // Build the message with all CEF headers.
        CEFMessage.Builder builder = CEFMessage.builder();
        
        //Process Header
        String headerString = tokens.get(0);
        Matcher headerMatch = HEADER_REGEX.matcher(headerString);

        if(headerMatch.find()) {
            //The header contains:
            //Group1 - the date [optional]
            //Group2 - the CEF version.
            
            //Fill in the current if no date header exists.
            DateTime timestamp;
            if (headerMatch.group(1) == null || headerMatch.group(1).isEmpty()) {
                // no syslog timestamp, using current time
                timestamp = DateTime.now(timezone);
            } else {
                timestamp = DateTime.parse(headerMatch.group(1), TIMESTAMP_PATTERN)
                        .withYear(DateTime.now(timezone).getYear())
                        .withZoneRetainFields(timezone);
            }

            builder.timestamp(timestamp);
            builder.version(Integer.valueOf(headerMatch.group(2)));
        } else {
            throw new ParserException("This message was not recognized as CEF and could not be parsed.");
        }
        
        builder.deviceVendor(tokens.get(1));
        builder.deviceProduct(tokens.get(2));
        builder.deviceVersion(tokens.get(3));
        builder.deviceEventClassId(tokens.get(4));
        builder.name(tokens.get(5));
        
        String severity_string = tokens.get(6);
        builder.severity(parseSeverity(severity_string));

        String fieldsString = tokens.get(7);
        if (fieldsString == null || fieldsString.isEmpty()) {
            throw new ParserException("No CEF payload found. Skipping this message.");
        } else {
            ImmutableMap<String, Object> parsedFields = FIELDS_PARSER.parse(fieldsString);
            builder.fields(parsedFields);
            //For now, keeping the duplicated message field. Will refactor later.
            if (parsedFields.containsKey("msg")){
                builder.message(String.valueOf(parsedFields.get("msg")));
            } else {
                //For compatibility, set message to null.
                builder.message(null);
            }
        }
        
        return builder.build();
    }

    private class ParserException extends Exception {

        public ParserException(String msg) {
            super(msg);
        }

    }

}
