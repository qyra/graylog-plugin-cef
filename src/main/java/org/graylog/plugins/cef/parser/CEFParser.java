package org.graylog.plugins.cef.parser;

import autovalue.shaded.com.google.common.common.collect.ImmutableMap;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CEFParser {

    /*
     * TODO:
     *   - benchmark regex
     */

    private static final Pattern HEADER_PATTERN = Pattern.compile("(?:^<\\d+>([a-zA-Z]{3}\\s+\\d{1,2} \\d{1,2}:\\d{1,2}:\\d{1,2}).*|^)CEF:(\\d+?)\\|(.+?)\\|(.+?)\\|(.+?)\\|(.+?)\\|(.+?)\\|(.+?)\\|(.+?)(?:$| (msg=.+))", Pattern.DOTALL);
    private static final DateTimeFormatter TIMESTAMP_PATTERN = DateTimeFormat.forPattern("MMM dd HH:mm:ss");

    private static final CEFFieldsParser FIELDS_PARSER = new CEFFieldsParser();

    private final DateTimeZone timezone;

    public CEFParser(DateTimeZone timezone) {
        this.timezone = timezone;
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

    public CEFMessage parse(String x) throws ParserException {
        Matcher m = HEADER_PATTERN.matcher(x);

        if(m.find()) {

            // Build the message with all CEF headers.
            CEFMessage.Builder builder = CEFMessage.builder();
            DateTime timestamp;
            if (m.group(1) == null || m.group(1).isEmpty()) {
                // no syslog timestamp, using current time
                timestamp = DateTime.now(timezone);
            } else {
                timestamp = DateTime.parse(m.group(1), TIMESTAMP_PATTERN)
                        .withYear(DateTime.now(timezone).getYear())
                        .withZoneRetainFields(timezone);
            }

            builder.timestamp(timestamp);
            builder.version(Integer.valueOf(m.group(2)));
            builder.deviceVendor(m.group(3));
            builder.deviceProduct(m.group(4));
            builder.deviceVersion(m.group(5));
            builder.deviceEventClassId(m.group(6));
            builder.name(m.group(7));
            
            String severity_string = m.group(8);
            int numeric_severity = parseSeverity(severity_string);
            builder.severity(numeric_severity);

            // Parse and add all CEF fields.
            String fieldsString = m.group(9);
            if (fieldsString == null || fieldsString.isEmpty()) {
                throw new ParserException("No CEF payload found. Skipping this message.");
            } else {
                builder.fields(FIELDS_PARSER.parse(fieldsString));
            }

            /*
             * The msg field and funky whitespace issues have to be handled differently.
             * The standard says that this message is always at the end of the whole CEF
             * message. This parser will only work if that is indeed the case.
             *
             * Optional. Not all message have this and we'e ok with that fact. /shrug
             */
            if(m.group(10) != null && !m.group(10).isEmpty()) {
                // This message has a msg field.
                builder.message(m.group(10).substring(4)); // cut off 'msg=' part instead of going crazy with regex capture group.
            } else {
                builder.message(null);
            }
            return builder.build();
        } else {
            throw new ParserException("This message was not recognized as CEF and could not be parsed.");
        }
    }

    private class ParserException extends Exception {

        public ParserException(String msg) {
            super(msg);
        }

    }

}
