package org.graylog.plugins.cef.parser;

import autovalue.shaded.com.google.common.common.collect.ImmutableMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.ArrayList;

public class CEFFieldsParser {
    private static final Logger LOG = LoggerFactory.getLogger(CEFFieldsParser.class);

    //Splits fields string into a vector of:
    //key, value, key, value, key, value
    //To be assembled into a dict later.
    public static ArrayList<String> fieldSplit(String in){
        boolean escaped = false;
        ArrayList<String> tokens = new ArrayList<String>();
        StringBuilder curr = new StringBuilder();
        
        String currentKey = "";
        
        for (int i = 0; i < in.length(); i++){
            char c = in.charAt(i);
            
            if (escaped){
                escaped = false;
                switch (c){
                case '\\':
                    curr.append('\\');
                    break;
                case '=':
                    curr.append('=');
                    break;
                default:
                    //Found a character which should not be escaped.
                    tokens = new ArrayList<String>();
                    tokens.add("ERROR");
                    return tokens;
                }
                
            } else {
                switch (c){
                case '\\':
                    escaped = true;
                    break;
                case '=':
                    //This means that the preceding characters were the name of a key, and the next characters will be the value.
                    String preceding = curr.toString();
                    int spaceIndex = preceding.lastIndexOf(' ');

                    //If this is the first key, there will be no previous spaces.
                    if (spaceIndex == -1){
                        //This was the first keyname. There are no spaces, so the whole thing is a key.
                        currentKey = preceding;
                    } else {
                        //preceding contains a value, a space, then a key. Split the value and key.
                        String currentValue = preceding.substring(0, spaceIndex);
                        
                        tokens.add(currentKey);
                        tokens.add(currentValue);
                        
                        currentKey = preceding.substring(spaceIndex+1, preceding.length());
                    }
                    
                    curr = new StringBuilder();
                    break;
                default:
                    curr.append(c);
                }
            }
        }
        
        tokens.add(currentKey);
        tokens.add(curr.toString());
        
        return tokens;
    }

    public ImmutableMap<String, Object> parse(String x) {
        ArrayList<String> keysAndValues = fieldSplit(x);

        // Parse out all fields into a map.
        ImmutableMap.Builder<String, String> fieldsBuilder = new ImmutableMap.Builder<>();
        for(int i = 0; i < keysAndValues.size() -1; i = i + 2){
            fieldsBuilder.put(keysAndValues.get(i), keysAndValues.get(i+1));
        }

        ImmutableMap<String, String> fields;
        try {
            fields = fieldsBuilder.build();
        } catch(IllegalArgumentException e) {
            LOG.warn("Skipping malformed CEF message. Multiple keys with same name?");
            return null;
        }

        // Build a final set of fields.
        ImmutableMap.Builder<String, Object> resultBuilder = new ImmutableMap.Builder<>();
        for (Map.Entry<String, String> field : fields.entrySet()) {
            try {
                // Specifically handle everything that needs mapping or is not of type String.
                switch (field.getKey()) {
                    // Custom IPv6 fields. (we keep it as String)
                    case "c6a1":
                    case "c6a2":
                    case "c6a3":
                    case "c6a4":
                        resultBuilder.put(fields.get(getLabelFromValue(field.getKey())), field.getValue());
                        break;

                    // Custom floating points.
                    case "cfp1":
                    case "cfp2":
                    case "cfp3":
                    case "cfp4":
                        resultBuilder.put(fields.get(getLabelFromValue(field.getKey())), Float.valueOf(field.getValue()));
                        break;

                    // Custom longs. (only going to 3 for some reason /shrug)
                    case "cn1":
                    case "cn2":
                    case "cn3":
                    case "flexNumber1":
                    case "flexNumber2":
                        resultBuilder.put(fields.get(getLabelFromValue(field.getKey())), Long.valueOf(field.getValue()));
                        break;

                    // Custom strings.
                    case "cs1":
                    case "cs2":
                    case "cs3":
                    case "cs4":
                    case "cs5":
                    case "cs6":
                    case "flexString1":
                    case "flexString2":
                        resultBuilder.put(fields.get(getLabelFromValue(field.getKey())), field.getValue());
                        break;

                    // Custom timestamps. (we keep it as String) - This is where CEF suddenly breaks the naming scheme.
                    case "deviceCustomDate1":
                    case "deviceCustomDate2":
                    case "flexDate1":
                        resultBuilder.put(fields.get(getLabelFromValue(field.getKey())), field.getValue());
                        break;

                    // Direct integer conversions.
                    case "cnt":
                    case "destinationTranslatedPort":
                    case "deviceDirection":
                    case "dpid":
                    case "dpt":
                    case "dvcpid":
                    case "fsize":
                    case "in":
                    case "oldFileSize":
                    case "sourceTranslatedPort":
                    case "spid":
                    case "spt":
                    case "type":
                    case "uid":
                    case "euid":
                        resultBuilder.put(field.getKey(), Integer.valueOf(field.getValue()));
                        break;

                    // Direct double conversions.
                    case "dlat":
                    case "dlong":
                    case "slat":
                    case "slong":
                        resultBuilder.put(field.getKey(), Double.valueOf(field.getValue()));
                        break;

                    // Direct long conversions.
                    case "eventId":
                        resultBuilder.put(field.getKey(), Long.valueOf(field.getValue()));
                        break;

                    // All standard strings.
                    default:
                        // Add all standard strings but never the custom fields/extension field labels.
                        if(!field.getKey().endsWith("Label")) {
                            resultBuilder.put(field.getKey(), field.getValue());
                        }
                        break;
                }
            } catch (Exception e) {
                LOG.warn("Could not transform CEF field [{}] according to standard. Skipping.", field.getKey(), e);
            }
        }

        return resultBuilder.build();
    }

    private String getLabelFromValue(String valueName) {
        return valueName + "Label";
    }

}
