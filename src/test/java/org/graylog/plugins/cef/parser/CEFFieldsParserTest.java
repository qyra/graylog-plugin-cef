package org.graylog.plugins.cef.parser;

import autovalue.shaded.com.google.common.common.collect.ImmutableMap;
import org.junit.Test;
import java.util.ArrayList;
import java.util.Arrays;

import static org.junit.Assert.*;

public class CEFFieldsParserTest {

    @Test
    public void testParseCustomIPv6() throws Exception {
        CEFFieldsParser p = new CEFFieldsParser();
        ImmutableMap<String, Object> r = p.parse("dvc=ip-172-30-2-212 c6a1=fe80::5626:96ff:fed0:943 c6a1Label=TestTest cs2=ip-172-30-2-212->/var/log/auth.log cs2Label=Location msg=Aug 14 14:26:53 ip-172-30-2-212 sshd[16217]: message repeated 2 times");
        assertEquals("fe80::5626:96ff:fed0:943", r.get("TestTest"));
    }

    @Test
    public void testParseCustomFloat() throws Exception {
        CEFFieldsParser p = new CEFFieldsParser();
        ImmutableMap<String, Object> r = p.parse("dvc=ip-172-30-2-212 cfp2=90.01 cfp2Label=TestTest cs2=ip-172-30-2-212->/var/log/auth.log cs2Label=Location msg=Aug 14 14:26:53 ip-172-30-2-212 sshd[16217]: message repeated 2 times");
        assertEquals(90.01F, r.get("TestTest"));
    }

    @Test
    public void testParseCustomLong() throws Exception {
        CEFFieldsParser p = new CEFFieldsParser();
        ImmutableMap<String, Object> r = p.parse("dvc=ip-172-30-2-212 cn1=999999999999 cn1Label=TestTest cs2=ip-172-30-2-212->/var/log/auth.log cs2Label=Location msg=Aug 14 14:26:53 ip-172-30-2-212 sshd[16217]: message repeated 2 times");
        assertEquals(999999999999L, r.get("TestTest"));
    }

    @Test
    public void testParseCustomLongFlex() throws Exception {
        CEFFieldsParser p = new CEFFieldsParser();
        ImmutableMap<String, Object> r = p.parse("dvc=ip-172-30-2-212 flexNumber2=999999999999 flexNumber2Label=TestTest cs2=ip-172-30-2-212->/var/log/auth.log cs2Label=Location msg=Aug 14 14:26:53 ip-172-30-2-212 sshd[16217]: message repeated 2 times");
        assertEquals(999999999999L, r.get("TestTest"));
    }

    @Test
    public void testParseCustomString() throws Exception {
        CEFFieldsParser p = new CEFFieldsParser();
        ImmutableMap<String, Object> r = p.parse("dvc=ip-172-30-2-212 cs5=Fooo! cs5Label=TestTest cs2=ip-172-30-2-212->/var/log/auth.log cs2Label=Location msg=Aug 14 14:26:53 ip-172-30-2-212 sshd[16217]: message repeated 2 times");
        assertEquals("Fooo!", r.get("TestTest"));
    }

    @Test
    public void testParseCustomStringFlex() throws Exception {
        CEFFieldsParser p = new CEFFieldsParser();
        ImmutableMap<String, Object> r = p.parse("dvc=ip-172-30-2-212 flexString1=Fooo! flexString1Label=TestTest cs2=ip-172-30-2-212->/var/log/auth.log cs2Label=Location msg=Aug 14 14:26:53 ip-172-30-2-212 sshd[16217]: message repeated 2 times");
        assertEquals("Fooo!", r.get("TestTest"));
    }

    @Test
    public void testParseCustomTimestamp() throws Exception {
        CEFFieldsParser p = new CEFFieldsParser();
        ImmutableMap<String, Object> r = p.parse("dvc=ip-172-30-2-212 deviceCustomDate1=2016-08-19T21:51:08+00:00 deviceCustomDate1Label=TestTest cs2=ip-172-30-2-212->/var/log/auth.log cs2Label=Location msg=Aug 14 14:26:53 ip-172-30-2-212 sshd[16217]: message repeated 2 times");
        assertEquals("2016-08-19T21:51:08+00:00", r.get("TestTest"));
    }

    @Test
    public void testParseCustomTimestampFlex() throws Exception {
        CEFFieldsParser p = new CEFFieldsParser();
        ImmutableMap<String, Object> r = p.parse("dvc=ip-172-30-2-212 flexDate1=2016-08-19T21:51:08+00:00 flexDate1Label=TestTest cs2=ip-172-30-2-212->/var/log/auth.log cs2Label=Location msg=Aug 14 14:26:53 ip-172-30-2-212 sshd[16217]: message repeated 2 times");
        assertEquals("2016-08-19T21:51:08+00:00", r.get("TestTest"));
    }

    @Test
    public void testParseCustomMixed() throws Exception {
        CEFFieldsParser p = new CEFFieldsParser();
        ImmutableMap<String, Object> r = p.parse("dvc=ip-172-30-2-212 cn1=999999999999 cn1Label=TestTest cfp2=90.01 cfp2Label=TestTest2 cs2=ip-172-30-2-212->/var/log/auth.log cs2Label=Location msg=Aug 14 14:26:53 ip-172-30-2-212 sshd[16217]: message repeated 2 times");
        assertEquals(999999999999L, r.get("TestTest"));
        assertEquals(90.01F, r.get("TestTest2"));
    }

    @Test
    public void testParseStandardString() throws Exception {
        CEFFieldsParser p = new CEFFieldsParser();
        ImmutableMap<String, Object> r = p.parse("dvc=ip-172-30-2-212 cs2=ip-172-30-2-212->/var/log/auth.log cs2Label=Location msg=Aug 14 14:26:53 ip-172-30-2-212 sshd[16217]: message repeated 2 times");
        assertEquals("ip-172-30-2-212", r.get("dvc"));
    }

    @Test
    public void testParseStandardInteger() throws Exception {
        CEFFieldsParser p = new CEFFieldsParser();
        ImmutableMap<String, Object> r = p.parse("dvc=ip-172-30-2-212 cnt=3 destinationTranslatedPort=22 deviceDirection=1 dpid=9001 dpt=3342 dvcpid=900 fsize=12 in=543 oldFileSize=1000 sourceTranslatedPort=443 spid=5516 spt=22 type=0 cs2=ip-172-30-2-212->/var/log/auth.log cs2Label=Location msg=Aug 14 14:26:53 ip-172-30-2-212 sshd[16217]: message repeated 2 times");
        assertEquals(3, r.get("cnt"));
        assertEquals(22, r.get("destinationTranslatedPort"));
        assertEquals(1, r.get("deviceDirection"));
        assertEquals(9001, r.get("dpid"));
        assertEquals(3342, r.get("dpt"));
        assertEquals(900, r.get("dvcpid"));
        assertEquals(12, r.get("fsize"));
        assertEquals(543, r.get("in"));
        assertEquals(1000, r.get("oldFileSize"));
        assertEquals(443, r.get("sourceTranslatedPort"));
        assertEquals(5516, r.get("spid"));
        assertEquals(22, r.get("spt"));
        assertEquals(0, r.get("type"));
    }

    @Test
    public void testParseStandardDouble() throws Exception {
        CEFFieldsParser p = new CEFFieldsParser();
        ImmutableMap<String, Object> r = p.parse("dvc=ip-172-30-2-212 slat=29.7604 slong=95.3698 dlat=53.5511 dlong=9.9937 cs2=ip-172-30-2-212->/var/log/auth.log cs2Label=Location msg=Aug 14 14:26:53 ip-172-30-2-212 sshd[16217]: message repeated 2 times");
        assertEquals(29.7604D, r.get("slat"));
        assertEquals(95.3698, r.get("slong"));

        assertEquals(53.5511, r.get("dlat"));
        assertEquals(9.9937, r.get("dlong"));
    }

    @Test
    public void testParseStandardLong() throws Exception {
        CEFFieldsParser p = new CEFFieldsParser();
        ImmutableMap<String, Object> r = p.parse("dvc=ip-172-30-2-212 eventId=9001 cs2=ip-172-30-2-212->/var/log/auth.log cs2Label=Location msg=Aug 14 14:26:53 ip-172-30-2-212 sshd[16217]: message repeated 2 times");
        assertEquals(9001L, r.get("eventId"));
    }

    @Test
    public void testParseSpacedValues() throws Exception {
        CEFFieldsParser p = new CEFFieldsParser();
        ImmutableMap<String, Object> r = p.parse("dvc=ip-172-30-2-212 eventId=9001 cs2=ip-172-30-2-212 -> /var/log/auth.log cs2Label=Location msg=Aug 14 14:26:53 ip-172-30-2-212 sshd[16217]: message repeated 2 times");
        assertEquals("ip-172-30-2-212 -> /var/log/auth.log", r.get("Location"));
    }
    
    @Test
    public void testFieldAfterMessage() throws Exception {
        CEFFieldsParser p = new CEFFieldsParser();
        ImmutableMap<String, Object> r = p.parse("dvc=ip-172-30-2-212 eventId=9001 cs2=ip-172-30-2-212 -> /var/log/auth.log cs2Label=Location msg=Aug 14 14:26:53 ip-172-30-2-212 sshd[16217]: message repeated 2 times logname=name with spaces in it.txt uid=999");
        assertEquals("name with spaces in it.txt", r.get("logname"));
    }
    
    @Test
    public void testIntFieldAfterMessage() throws Exception {
        CEFFieldsParser p = new CEFFieldsParser();
        ImmutableMap<String, Object> r = p.parse("dvc=ip-172-30-2-212 eventId=9001 cs2=ip-172-30-2-212 -> /var/log/auth.log cs2Label=Location msg=Aug 14 14:26:53 ip-172-30-2-212 sshd[16217]: message repeated 2 times logname=name with spaces in it.txt uid=999");
        assertEquals(999, r.get("uid"));
    }
    
    //Testing the split function directly
    @Test
    public void testFieldSplitShort() {
        String input = "dvc=ip-172-30-2-212 cfp2=90.01";
        String[] exp = {"dvc", "ip-172-30-2-212", "cfp2", "90.01"};
        ArrayList<String> expected = new ArrayList<String>(Arrays.asList(exp));
        ArrayList<String> result = CEFFieldsParser.fieldSplit(input);
        assertEquals(expected, result);
    }
    
    @Test
    public void testFieldTrailingSpaces() {
        //Only the last space before a key should be stripped. All other
        //trailing whitespace belongs to the preceding value and should
        //not be removed. (As per the official CEF specification)
        //So 2 trailing spaces in the input-> 1 in the field value output, 3->2, etc.
        String input = "dvc=ip-172-30-2-212   cfp2=90.01 cfp2Label=SomeFloat  spt=  22     cs2=ip-172-30-2-212->/var/log/auth.log cs2Label=Location msg=Aug 14 14:26:53 ip-172-30-2-212 sshd[16217]: PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=8.8.8.8  user=root";
        String[] exp = {"dvc", "ip-172-30-2-212  ", "cfp2", "90.01", "cfp2Label", "SomeFloat ", "spt", "  22    ", "cs2", "ip-172-30-2-212->/var/log/auth.log", "cs2Label", "Location", "msg", "Aug 14 14:26:53 ip-172-30-2-212 sshd[16217]: PAM 2 more authentication failures;", "logname", "", "uid", "0", "euid", "0",  "tty", "ssh", "ruser", "", "rhost", "8.8.8.8 ", "user", "root"};
        ArrayList<String> expected = new ArrayList<String>(Arrays.asList(exp));
        ArrayList<String> result = CEFFieldsParser.fieldSplit(input);
        assertEquals(expected, result);
    }
    
    @Test
    public void testEscapedEquals() {
        //Equals signs are allowed in field values, as long as they are
        //escapes with a backslash.
        String input = "dvc=ip-172-30-2-212  cfp2=90.01 cfp2Label=SomeFloat\\=  spt=22 cs2=ip-172-30-2-212->/var/log/auth.log cs2Label=Location msg=\\=Have some \\=escaped\\= equals!\\= logname= uid=0 euid=0 tty=ssh ruser= rhost=8.8.8.8  user=root";
        String[] exp = {"dvc", "ip-172-30-2-212 ", "cfp2", "90.01", "cfp2Label", "SomeFloat= ", "spt", "22", "cs2", "ip-172-30-2-212->/var/log/auth.log", "cs2Label", "Location", "msg", "=Have some =escaped= equals!=", "logname", "", "uid", "0", "euid", "0",  "tty", "ssh", "ruser", "", "rhost", "8.8.8.8 ", "user", "root"};
        ArrayList<String> expected = new ArrayList<String>(Arrays.asList(exp));
        ArrayList<String> result = CEFFieldsParser.fieldSplit(input);
        assertEquals(expected, result);
    }
    
    @Test
    public void testEscapedEscapeAtEnd() {
        //Equals signs are allowed in field values, as long as they are
        //escapes with a backslash.
        String input = "dvc=ip-172-30-2-212  cfp2=90.01 cfp2Label=SomeFloat\\=  spt=22 cs2=ip-172-30-2-212->/var/log/auth.log cs2Label=Location msg=\\=Have some \\=escaped\\= equals!\\= logname= uid=0 euid=0 tty=ssh ruser= rhost=8.8.8.8  user=root\\\\";
        String[] exp = {"dvc", "ip-172-30-2-212 ", "cfp2", "90.01", "cfp2Label", "SomeFloat= ", "spt", "22", "cs2", "ip-172-30-2-212->/var/log/auth.log", "cs2Label", "Location", "msg", "=Have some =escaped= equals!=", "logname", "", "uid", "0", "euid", "0",  "tty", "ssh", "ruser", "", "rhost", "8.8.8.8 ", "user", "root\\"};
        ArrayList<String> expected = new ArrayList<String>(Arrays.asList(exp));
        ArrayList<String> result = CEFFieldsParser.fieldSplit(input);
        assertEquals(expected, result);
    }
    
    @Test
    public void testEscapedEqualsAtEnd() {
        //Equals signs are allowed in field values, as long as they are
        //escapes with a backslash.
        String input = "dvc=ip-172-30-2-212  cfp2=90.01 cfp2Label=SomeFloat\\=  spt=22 cs2=ip-172-30-2-212->/var/log/auth.log cs2Label=Location msg=\\=Have some \\=escaped\\= equals!\\= logname= uid=0 euid=0 tty=ssh ruser= rhost=8.8.8.8  user=root\\=";
        String[] exp = {"dvc", "ip-172-30-2-212 ", "cfp2", "90.01", "cfp2Label", "SomeFloat= ", "spt", "22", "cs2", "ip-172-30-2-212->/var/log/auth.log", "cs2Label", "Location", "msg", "=Have some =escaped= equals!=", "logname", "", "uid", "0", "euid", "0",  "tty", "ssh", "ruser", "", "rhost", "8.8.8.8 ", "user", "root="};
        ArrayList<String> expected = new ArrayList<String>(Arrays.asList(exp));
        ArrayList<String> result = CEFFieldsParser.fieldSplit(input);
        assertEquals(expected, result);
    }
}
