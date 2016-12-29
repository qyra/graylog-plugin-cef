package org.graylog.plugins.cef.parser;

import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Test;
import java.util.ArrayList;
import java.util.Arrays;
import static org.junit.Assert.*;

@SuppressWarnings("Duplicates")
public class CEFParserTest {

    @Test
    public void testParse() throws Exception {
        int year = DateTime.now(DateTimeZone.getDefault()).getYear();

        CEFParser parser = new CEFParser(DateTimeZone.UTC);
        CEFMessage m = parser.parse("<132>Aug 14 14:26:55 CEF:0|Trend Micro Inc.|OSSEC HIDS|v2.8.3|2502|User missed the password more than one time|10|dvc=ip-172-30-2-212 cfp2=90.01 cfp2Label=SomeFloat spt=22 cs2=ip-172-30-2-212->/var/log/auth.log cs2Label=Location msg=Aug 14 14:26:53 ip-172-30-2-212 sshd[16217]: PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=116.31.116.17  user=root");

        DateTime timestamp = m.timestamp().withZone(DateTimeZone.UTC);

        // THIS WILL BREAK ON NEW YEARS EVE FOR A MOMENT and I don't care
        assertEquals(year, timestamp.getYear());
        assertEquals(8, timestamp.getMonthOfYear());
        assertEquals(14, timestamp.getDayOfMonth());
        assertEquals(14, timestamp.getHourOfDay());
        assertEquals(26, timestamp.getMinuteOfHour());
        assertEquals(55, timestamp.getSecondOfMinute());

        assertEquals(0, m.version());
        assertEquals("Trend Micro Inc.", m.deviceVendor());
        assertEquals("OSSEC HIDS", m.deviceProduct());
        assertEquals("v2.8.3", m.deviceVersion());
        assertEquals("2502", m.deviceEventClassId());
        assertEquals("User missed the password more than one time", m.name());
        assertEquals(10, m.severity());
        assertEquals("VERY HIGH", m.humanReadableSeverity());

        assertEquals("Aug 14 14:26:53 ip-172-30-2-212 sshd[16217]: PAM 2 more authentication failures;", m.message());

        assertEquals("ip-172-30-2-212", m.fields().get("dvc"));
        assertEquals(22, m.fields().get("spt"));
        assertEquals(90.01F, m.fields().get("SomeFloat"));
        assertEquals("ip-172-30-2-212->/var/log/auth.log", m.fields().get("Location"));
    }

    @Test
    public void testParseLowSeverity() throws Exception {
        int year = DateTime.now(DateTimeZone.getDefault()).getYear();

        CEFParser parser = new CEFParser(DateTimeZone.UTC);
        CEFMessage m = parser.parse("<132>Aug 14 14:26:55 CEF:0|Trend Micro Inc.|OSSEC HIDS|v2.8.3|2502|User missed the password more than one time|Low|dvc=ip-172-30-2-212 cfp2=90.01 cfp2Label=SomeFloat spt=22 cs2=ip-172-30-2-212->/var/log/auth.log cs2Label=Location msg=Aug 14 14:26:53 ip-172-30-2-212 sshd[16217]: PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=116.31.116.17  user=root");

        DateTime timestamp = m.timestamp().withZone(DateTimeZone.UTC);

        // THIS WILL BREAK ON NEW YEARS EVE FOR A MOMENT and I don't care
        assertEquals(year, timestamp.getYear());
        assertEquals(8, timestamp.getMonthOfYear());
        assertEquals(14, timestamp.getDayOfMonth());
        assertEquals(14, timestamp.getHourOfDay());
        assertEquals(26, timestamp.getMinuteOfHour());
        assertEquals(55, timestamp.getSecondOfMinute());

        assertEquals(0, m.version());
        assertEquals("Trend Micro Inc.", m.deviceVendor());
        assertEquals("OSSEC HIDS", m.deviceProduct());
        assertEquals("v2.8.3", m.deviceVersion());
        assertEquals("2502", m.deviceEventClassId());
        assertEquals("User missed the password more than one time", m.name());
        assertEquals(3, m.severity());
        assertEquals("LOW", m.humanReadableSeverity());

        assertEquals("Aug 14 14:26:53 ip-172-30-2-212 sshd[16217]: PAM 2 more authentication failures;", m.message());

        assertEquals("ip-172-30-2-212", m.fields().get("dvc"));
        assertEquals(22, m.fields().get("spt"));
        assertEquals(90.01F, m.fields().get("SomeFloat"));
        assertEquals("ip-172-30-2-212->/var/log/auth.log", m.fields().get("Location"));
    }
    
    @Test
    public void testParseMedSeverity() throws Exception {
        int year = DateTime.now(DateTimeZone.getDefault()).getYear();

        CEFParser parser = new CEFParser(DateTimeZone.UTC);
        CEFMessage m = parser.parse("<132>Aug 14 14:26:55 CEF:0|Trend Micro Inc.|OSSEC HIDS|v2.8.3|2502|User missed the password more than one time|Medium|dvc=ip-172-30-2-212 cfp2=90.01 cfp2Label=SomeFloat spt=22 cs2=ip-172-30-2-212->/var/log/auth.log cs2Label=Location msg=Aug 14 14:26:53 ip-172-30-2-212 sshd[16217]: PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=116.31.116.17  user=root");

        DateTime timestamp = m.timestamp().withZone(DateTimeZone.UTC);

        // THIS WILL BREAK ON NEW YEARS EVE FOR A MOMENT and I don't care
        assertEquals(year, timestamp.getYear());
        assertEquals(8, timestamp.getMonthOfYear());
        assertEquals(14, timestamp.getDayOfMonth());
        assertEquals(14, timestamp.getHourOfDay());
        assertEquals(26, timestamp.getMinuteOfHour());
        assertEquals(55, timestamp.getSecondOfMinute());

        assertEquals(0, m.version());
        assertEquals("Trend Micro Inc.", m.deviceVendor());
        assertEquals("OSSEC HIDS", m.deviceProduct());
        assertEquals("v2.8.3", m.deviceVersion());
        assertEquals("2502", m.deviceEventClassId());
        assertEquals("User missed the password more than one time", m.name());
        assertEquals(6, m.severity());
        assertEquals("MEDIUM", m.humanReadableSeverity());

        assertEquals("Aug 14 14:26:53 ip-172-30-2-212 sshd[16217]: PAM 2 more authentication failures;", m.message());

        assertEquals("ip-172-30-2-212", m.fields().get("dvc"));
        assertEquals(22, m.fields().get("spt"));
        assertEquals(90.01F, m.fields().get("SomeFloat"));
        assertEquals("ip-172-30-2-212->/var/log/auth.log", m.fields().get("Location"));
    }
    
    @Test
    public void testParseHighSeverity() throws Exception {
        int year = DateTime.now(DateTimeZone.getDefault()).getYear();

        CEFParser parser = new CEFParser(DateTimeZone.UTC);
        CEFMessage m = parser.parse("<132>Aug 14 14:26:55 CEF:0|Trend Micro Inc.|OSSEC HIDS|v2.8.3|2502|User missed the password more than one time|High|dvc=ip-172-30-2-212 cfp2=90.01 cfp2Label=SomeFloat spt=22 cs2=ip-172-30-2-212->/var/log/auth.log cs2Label=Location msg=Aug 14 14:26:53 ip-172-30-2-212 sshd[16217]: PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=116.31.116.17  user=root");

        DateTime timestamp = m.timestamp().withZone(DateTimeZone.UTC);

        // THIS WILL BREAK ON NEW YEARS EVE FOR A MOMENT and I don't care
        assertEquals(year, timestamp.getYear());
        assertEquals(8, timestamp.getMonthOfYear());
        assertEquals(14, timestamp.getDayOfMonth());
        assertEquals(14, timestamp.getHourOfDay());
        assertEquals(26, timestamp.getMinuteOfHour());
        assertEquals(55, timestamp.getSecondOfMinute());

        assertEquals(0, m.version());
        assertEquals("Trend Micro Inc.", m.deviceVendor());
        assertEquals("OSSEC HIDS", m.deviceProduct());
        assertEquals("v2.8.3", m.deviceVersion());
        assertEquals("2502", m.deviceEventClassId());
        assertEquals("User missed the password more than one time", m.name());
        assertEquals(8, m.severity());
        assertEquals("HIGH", m.humanReadableSeverity());

        assertEquals("Aug 14 14:26:53 ip-172-30-2-212 sshd[16217]: PAM 2 more authentication failures;", m.message());

        assertEquals("ip-172-30-2-212", m.fields().get("dvc"));
        assertEquals(22, m.fields().get("spt"));
        assertEquals(90.01F, m.fields().get("SomeFloat"));
        assertEquals("ip-172-30-2-212->/var/log/auth.log", m.fields().get("Location"));
    }
    
    @Test
    public void testParseVeryHighSeverity() throws Exception {
        int year = DateTime.now(DateTimeZone.getDefault()).getYear();

        CEFParser parser = new CEFParser(DateTimeZone.UTC);
        CEFMessage m = parser.parse("<132>Aug 14 14:26:55 CEF:0|Trend Micro Inc.|OSSEC HIDS|v2.8.3|2502|User missed the password more than one time|Very-High|dvc=ip-172-30-2-212 cfp2=90.01 cfp2Label=SomeFloat spt=22 cs2=ip-172-30-2-212->/var/log/auth.log cs2Label=Location msg=Aug 14 14:26:53 ip-172-30-2-212 sshd[16217]: PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=116.31.116.17  user=root");

        DateTime timestamp = m.timestamp().withZone(DateTimeZone.UTC);

        // THIS WILL BREAK ON NEW YEARS EVE FOR A MOMENT and I don't care
        assertEquals(year, timestamp.getYear());
        assertEquals(8, timestamp.getMonthOfYear());
        assertEquals(14, timestamp.getDayOfMonth());
        assertEquals(14, timestamp.getHourOfDay());
        assertEquals(26, timestamp.getMinuteOfHour());
        assertEquals(55, timestamp.getSecondOfMinute());

        assertEquals(0, m.version());
        assertEquals("Trend Micro Inc.", m.deviceVendor());
        assertEquals("OSSEC HIDS", m.deviceProduct());
        assertEquals("v2.8.3", m.deviceVersion());
        assertEquals("2502", m.deviceEventClassId());
        assertEquals("User missed the password more than one time", m.name());
        assertEquals(10, m.severity());
        assertEquals("VERY HIGH", m.humanReadableSeverity());

        assertEquals("Aug 14 14:26:53 ip-172-30-2-212 sshd[16217]: PAM 2 more authentication failures;", m.message());

        assertEquals("ip-172-30-2-212", m.fields().get("dvc"));
        assertEquals(22, m.fields().get("spt"));
        assertEquals(90.01F, m.fields().get("SomeFloat"));
        assertEquals("ip-172-30-2-212->/var/log/auth.log", m.fields().get("Location"));
    }
    
    @Test
    public void testParseUnknownSeverity() throws Exception {
        int year = DateTime.now(DateTimeZone.getDefault()).getYear();

        CEFParser parser = new CEFParser(DateTimeZone.UTC);
        CEFMessage m = parser.parse("<132>Aug 14 14:26:55 CEF:0|Trend Micro Inc.|OSSEC HIDS|v2.8.3|2502|User missed the password more than one time|Unknown|dvc=ip-172-30-2-212 cfp2=90.01 cfp2Label=SomeFloat spt=22 cs2=ip-172-30-2-212->/var/log/auth.log cs2Label=Location msg=Aug 14 14:26:53 ip-172-30-2-212 sshd[16217]: PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=116.31.116.17  user=root");

        DateTime timestamp = m.timestamp().withZone(DateTimeZone.UTC);

        // THIS WILL BREAK ON NEW YEARS EVE FOR A MOMENT and I don't care
        assertEquals(year, timestamp.getYear());
        assertEquals(8, timestamp.getMonthOfYear());
        assertEquals(14, timestamp.getDayOfMonth());
        assertEquals(14, timestamp.getHourOfDay());
        assertEquals(26, timestamp.getMinuteOfHour());
        assertEquals(55, timestamp.getSecondOfMinute());

        assertEquals(0, m.version());
        assertEquals("Trend Micro Inc.", m.deviceVendor());
        assertEquals("OSSEC HIDS", m.deviceProduct());
        assertEquals("v2.8.3", m.deviceVersion());
        assertEquals("2502", m.deviceEventClassId());
        assertEquals("User missed the password more than one time", m.name());
        assertEquals(-1, m.severity());
        assertEquals("UNKNOWN", m.humanReadableSeverity());

        assertEquals("Aug 14 14:26:53 ip-172-30-2-212 sshd[16217]: PAM 2 more authentication failures;", m.message());

        assertEquals("ip-172-30-2-212", m.fields().get("dvc"));
        assertEquals(22, m.fields().get("spt"));
        assertEquals(90.01F, m.fields().get("SomeFloat"));
        assertEquals("ip-172-30-2-212->/var/log/auth.log", m.fields().get("Location"));
    }

    @Test
    public void testParseWithMissingMsgField() throws Exception {
        int year = DateTime.now(DateTimeZone.getDefault()).getYear();

        CEFParser parser = new CEFParser(DateTimeZone.UTC);
        CEFMessage m = parser.parse("<132>Aug 14 14:26:55 CEF:0|Trend Micro Inc.|OSSEC HIDS|v2.8.3|2502|User missed the password more than one time|10|dvc=ip-172-30-2-212 cs2=ip-172-30-2-212->/var/log/auth.log cs2Label=Location cfp2=90.01 cfp2Label=SomeFloat spt=22");

        DateTime timestamp = m.timestamp().withZone(DateTimeZone.UTC);

        // THIS WILL BREAK ON NEW YEARS EVE FOR A MOMENT and I don't care
        assertEquals(year, timestamp.getYear());
        assertEquals(8, timestamp.getMonthOfYear());
        assertEquals(14, timestamp.getDayOfMonth());
        assertEquals(14, timestamp.getHourOfDay());
        assertEquals(26, timestamp.getMinuteOfHour());
        assertEquals(55, timestamp.getSecondOfMinute());

        assertEquals(0, m.version());
        assertEquals("Trend Micro Inc.", m.deviceVendor());
        assertEquals("OSSEC HIDS", m.deviceProduct());
        assertEquals("v2.8.3", m.deviceVersion());
        assertEquals("2502", m.deviceEventClassId());
        assertEquals("User missed the password more than one time", m.name());
        assertEquals(10, m.severity());
        assertEquals("VERY HIGH", m.humanReadableSeverity());

        assertNull(m.message());

        assertEquals("ip-172-30-2-212", m.fields().get("dvc"));
        assertEquals(22, m.fields().get("spt"));
        assertEquals(90.01F, m.fields().get("SomeFloat"));
        assertEquals("ip-172-30-2-212->/var/log/auth.log", m.fields().get("Location"));
    }

    @Test
    public void testParseUsesProvidedTimezone() throws Exception {
        CEFParser parser = new CEFParser(DateTimeZone.UTC);
        CEFMessage m = parser.parse("<132>Aug 14 14:26:55 CEF:0|Trend Micro Inc.|OSSEC HIDS|v2.8.3|2502|User missed the password more than one time|10|dvc=ip-172-30-2-212 cs2=ip-172-30-2-212->/var/log/auth.log cs2Label=Location cfp2=90.01 cfp2Label=SomeFloat spt=22");

        assertEquals("UTC", m.timestamp().getZone().toString());

        CEFParser parser2 = new CEFParser(DateTimeZone.forID("+01:00"));
        CEFMessage m2 = parser2.parse("<132>Aug 14 14:26:55 CEF:0|Trend Micro Inc.|OSSEC HIDS|v2.8.3|2502|User missed the password more than one time|10|dvc=ip-172-30-2-212 cs2=ip-172-30-2-212->/var/log/auth.log cs2Label=Location cfp2=90.01 cfp2Label=SomeFloat spt=22");

        assertEquals("+01:00", m2.timestamp().getZone().toString());
    }

    @Test
    public void testParseWithSyslogHost() throws Exception {
        int year = DateTime.now(DateTimeZone.getDefault()).getYear();

        CEFParser parser = new CEFParser(DateTimeZone.UTC);
        CEFMessage m = parser.parse("<132>Aug 14 14:26:55 ossec-host CEF:0|Trend Micro Inc.|OSSEC HIDS|v2.8.3|2502|User missed the password more than one time|10|dvc=ip-172-30-2-212 cfp2=90.01 cfp2Label=SomeFloat spt=22 cs2=ip-172-30-2-212->/var/log/auth.log cs2Label=Location msg=Aug 14 14:26:53 ip-172-30-2-212 sshd[16217]: PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=116.31.116.17  user=root");

        DateTime timestamp = m.timestamp().withZone(DateTimeZone.UTC);

        // THIS WILL BREAK ON NEW YEARS EVE FOR A MOMENT and I don't care
        assertEquals(year, timestamp.getYear());
        assertEquals(8, timestamp.getMonthOfYear());
        assertEquals(14, timestamp.getDayOfMonth());
        assertEquals(14, timestamp.getHourOfDay());
        assertEquals(26, timestamp.getMinuteOfHour());
        assertEquals(55, timestamp.getSecondOfMinute());

        assertEquals(0, m.version());
        assertEquals("Trend Micro Inc.", m.deviceVendor());
        assertEquals("OSSEC HIDS", m.deviceProduct());
        assertEquals("v2.8.3", m.deviceVersion());
        assertEquals("2502", m.deviceEventClassId());
        assertEquals("User missed the password more than one time", m.name());
        assertEquals(10, m.severity());
        assertEquals("VERY HIGH", m.humanReadableSeverity());

        assertEquals("Aug 14 14:26:53 ip-172-30-2-212 sshd[16217]: PAM 2 more authentication failures;", m.message());

        assertEquals("ip-172-30-2-212", m.fields().get("dvc"));
        assertEquals(22, m.fields().get("spt"));
        assertEquals(90.01F, m.fields().get("SomeFloat"));
        assertEquals("ip-172-30-2-212->/var/log/auth.log", m.fields().get("Location"));
    }



    @Test
    public void testParseWithoutSyslogPrefix() throws Exception {

        CEFParser parser = new CEFParser(DateTimeZone.UTC);
        CEFMessage m = parser.parse("CEF:0|Trend Micro Inc.|OSSEC HIDS|v2.8.3|2502|User missed the password more than one time|10|dvc=ip-172-30-2-212 cfp2=90.01 cfp2Label=SomeFloat spt=22 cs2=ip-172-30-2-212->/var/log/auth.log cs2Label=Location msg=Aug 14 14:26:53 ip-172-30-2-212 sshd[16217]: PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=116.31.116.17  user=root");

        DateTime timestamp = m.timestamp().withZone(DateTimeZone.UTC);
        DateTime now = DateTime.now(DateTimeZone.UTC);

        assertEquals(now.getYear(), timestamp.getYear());
        assertEquals(now.getMonthOfYear(), timestamp.getMonthOfYear());
        assertEquals(now.getDayOfMonth(), timestamp.getDayOfMonth());
        assertEquals(now.getHourOfDay(), timestamp.getHourOfDay());
        assertEquals(now.getMinuteOfHour(), timestamp.getMinuteOfHour());
        assertEquals(now.getSecondOfMinute(), timestamp.getSecondOfMinute());

        assertEquals(0, m.version());
        assertEquals("Trend Micro Inc.", m.deviceVendor());
        assertEquals("OSSEC HIDS", m.deviceProduct());
        assertEquals("v2.8.3", m.deviceVersion());
        assertEquals("2502", m.deviceEventClassId());
        assertEquals("User missed the password more than one time", m.name());
        assertEquals(10, m.severity());
        assertEquals("VERY HIGH", m.humanReadableSeverity());

        assertEquals("Aug 14 14:26:53 ip-172-30-2-212 sshd[16217]: PAM 2 more authentication failures;", m.message());

        assertEquals("ip-172-30-2-212", m.fields().get("dvc"));
        assertEquals(22, m.fields().get("spt"));
        assertEquals(90.01F, m.fields().get("SomeFloat"));
        assertEquals("ip-172-30-2-212->/var/log/auth.log", m.fields().get("Location"));
    }

    @Test
    public void testParseNessusEscapes() throws Exception {
        //A longer input with lots of escaped characters, to test
        //what nessus generates.
        CEFParser parser = new CEFParser(DateTimeZone.UTC);
        CEFMessage m = parser.parse("CEF:0|Nessus|Nessus||Nessus\\|18405|Operating System: Windows|2| eventId=6 categorySignificance=/Normal categoryBehavior=/Found categoryTechnique=/scanner/device/uri categoryDeviceGroup=/Assessment Tools categoryOutcome=/Success categoryObject=/Host art=1482522872412 deviceSeverity=Operating System rt=1482522872412 dst=8.8.8.8 destinationZoneURI=/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 192.168.0.0-192.168.255.255 filePath=/Site Asset Categories/Operating System/Microsoft Windows Server 2012 R2 Standard ahost=HOSTNAME.ANON agt=8.8.8.8 agentZoneURI=/All Zones/ArcSight System/Private Address Space Zones/RFC9999: 10.0.0.0-10.255.255.255 av=8.8.8.8 atz=America/Chicago at=nessus_dotnessus dtz=America/Chicago _cefVer=0.1 ad.PolicyUsed=Basic Network Scan ad.reportName=rcdc_uat_2016q4_noauth ad.os=windows ad.netbiosName=TEST ad.cpe0=cpe:/o:microsoft:windows_server_2012:r2 ad.CredentialedScan=false ad.cpe=cpe:/o:microsoft:windows ad.TracerouteHop0=8.8.8.8 ad.endTime.d=12/13/2016 15:32:13.000 CST ad.__FILE__PATH=C:\\\\Users\\\\ANON\\\\Desktop\\\\nessus_test\\\\rcdc_uat_2016q4_noauth_vjxnyn.nessus ad.PatchSummaryTotalCves=14 ad.LastUnauthenticatedResults=1481664733 aid=testtesttest\\\\\\=\\\\\\=");

        DateTime timestamp = m.timestamp().withZone(DateTimeZone.UTC);
        DateTime now = DateTime.now(DateTimeZone.UTC);

        assertEquals(now.getYear(), timestamp.getYear());
        assertEquals(now.getMonthOfYear(), timestamp.getMonthOfYear());
        assertEquals(now.getDayOfMonth(), timestamp.getDayOfMonth());
        assertEquals(now.getHourOfDay(), timestamp.getHourOfDay());
        assertEquals(now.getMinuteOfHour(), timestamp.getMinuteOfHour());
        assertEquals(now.getSecondOfMinute(), timestamp.getSecondOfMinute());

        assertEquals(0, m.version());
        assertEquals("Nessus", m.deviceVendor());
        assertEquals("Nessus", m.deviceProduct());
        assertEquals(2, m.severity());
        assertEquals("LOW", m.humanReadableSeverity());
        assertEquals("C:\\Users\\ANON\\Desktop\\nessus_test\\rcdc_uat_2016q4_noauth_vjxnyn.nessus", m.fields().get("ad.__FILE__PATH"));
        assertEquals("testtesttest\\=\\=", m.fields().get("aid"));
    }

    // Testing the splitter for pipe delimited messages:
    @Test
    public void testSplitSmallString() throws Exception{
        //If there are less than 8 tokens, the parser must throw an exception about this.
        CEFParser parser = new CEFParser(DateTimeZone.UTC);
        
        try {
            CEFMessage m = parser.parse("CEF:0|Trend Micro Inc.|OSSEC HIDS|v2.8.3|2502|User missed the password more than one time|10");
            throw new Exception("pipeSplit must throw a ParserException if less than 7 pipes are in the input. It did not, so it is not working correctly");
        } catch (Exception e){
            //Test passed, an exception was thrown as expected.
        }
    }
    
    @Test
    public void testSplit8() throws Exception{
        String input = "a|b|c|d|e|f|g|h";
        String[] exp = {"a", "b", "c", "d", "e", "f", "g", "h"};
        ArrayList<String> expected = new ArrayList<String>(Arrays.asList(exp));
        ArrayList<String> result = CEFParser.pipeSplit(input);
        assertEquals(expected, result);
    }
    
    @Test
    public void testSplit9() throws Exception{
        //Pipes should no longer split the input after 8 tokens are created.
        //The last token will contain all pipes as normal characters.
        String input = "a|b|c|d|e|f|g|h|i";
        String[] exp = {"a", "b", "c", "d", "e", "f", "g", "h|i"};
        ArrayList<String> expected = new ArrayList<String>(Arrays.asList(exp));
        ArrayList<String> result = CEFParser.pipeSplit(input);
        assertEquals(expected, result);
    }
    
    
    @Test
    public void testmissing() throws Exception{
        //The function should correctly handle empty tokens at any position.
        String input = "|||||||";
        String[] exp = {"", "", "", "", "", "", "", ""};
        ArrayList<String> expected = new ArrayList<String>(Arrays.asList(exp));
        ArrayList<String> result = CEFParser.pipeSplit(input);
        assertEquals(expected, result);
    }
    
    @Test
    public void testSplit9EscapeCodes() throws Exception{
        //Pipes and backslashes should be correctly escaped
        String input = "1a\\|1b|\\|2a2b\\||\\|3a3b\\\\|4|5|6|7|8";
        String[] exp = {"1a|1b", "|2a2b|", "|3a3b\\", "4", "5", "6", "7", "8"};
        ArrayList<String> expected = new ArrayList<String>(Arrays.asList(exp));
        ArrayList<String> result = CEFParser.pipeSplit(input);
        assertEquals(expected, result);
    }
}
