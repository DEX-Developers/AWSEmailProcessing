package com.dex;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SNSEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.json.JSONArray;
import org.json.JSONObject;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.sesv2.SesV2Client;
import software.amazon.awssdk.services.sesv2.model.EmailContent;
import software.amazon.awssdk.services.sesv2.model.SendEmailRequest;
import software.amazon.awssdk.services.sesv2.model.RawMessage;
import javax.mail.Part;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.MimeMultipart;
import javax.mail.internet.MimeMessage;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.util.*;

import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.sqs.model.SendMessageRequest;


/*Keys to form SQS message*/
enum sqsKeys {


    Category, ///*Possible Categories: Spam, Virus, Undeliverable, Unsubscribe, Autoanswer, HL*/
    S3ObjectLink,// link to email in S3
    From, //From
    Subject,
    MessageID, //Message ID that assign sender
    Date,
    InReplyTo //Message ID if email replied to our and this is potencial HL. Using our format
}
enum sqsCategories {
    Spam, Virus, ReportUndeliverable, ReportUnsubscribe, Unsubscribe, Autoanswer, HL, Other
}
public class Main implements RequestHandler<SNSEvent, String> {

    /*Define global variables*/
    /*#######################*/
    private final S3Client s3 = S3Client.create();
    private final SesV2Client ses = SesV2Client.create();
    private String bucketName;
    private String objectKey;
    private final String fromEmail = "jmark_processor@dex.com";  // Change this
    private String from;
    private String subject = "";
    private String contentType = "";
    private String messageId = "";
    private String inReplyTo = "";
    private String dateParsed = "";
    private JSONArray headers = new JSONArray(); //for parsing headers
    private JSONObject parsedSNS; //original event that came from SNS
    private String spamVerdict;
    private String virusVerdict;
    private String spfVerdict;
    private String dkimVerdict;
    private String dmarcVerdict;
    boolean toForward; //determine if we need to forward email to jmark or this is service email like undeliverables
    private Map<String, String> sqsNotification = new HashMap<>();
    private static final String QUEUE_URL = "https://sqs.us-west-2.amazonaws.com/073628739062/AWSEmailProcSQS"; //SQS URL
    private static final String SPAM_QUEUE_URL = "https://sqs.us-west-2.amazonaws.com/073628739062/AWSEmailProcSQS"; // URL to send SPAMS
    private static final Region region = Region.US_WEST_2;
    /*Keywords definition block*/
    /*Define subject keywords set*/
    HashSet<String> subjectUndeliverableKeywords = new HashSet<>();  //keywords in subject to parse message
    HashSet<String> subjectAutoanswerKeywords = new HashSet<>();  //keywords in subject to parse message
    /*End of Global Variables definition*/
    /*##################################*/

    /*Lambda initialization*/
    private void initialize(SNSEvent event) {
        parsedSNS = new JSONObject(event.getRecords().get(0).getSNS().getMessage());
        spamVerdict = parsedSNS.getJSONObject("receipt").getJSONObject("spamVerdict").getString("status");
        virusVerdict = parsedSNS.getJSONObject("receipt").getJSONObject("virusVerdict").getString("status");
        spfVerdict = parsedSNS.getJSONObject("receipt").getJSONObject("spfVerdict").getString("status");
        dkimVerdict = parsedSNS.getJSONObject("receipt").getJSONObject("dkimVerdict").getString("status");
        dmarcVerdict = parsedSNS.getJSONObject("receipt").getJSONObject("dmarcVerdict").getString("status");
        headers = parsedSNS.getJSONObject("mail").getJSONArray("headers");
        bucketName = parsedSNS.getJSONObject("receipt").getJSONObject("action").getString("bucketName");
        objectKey = parsedSNS.getJSONObject("receipt").getJSONObject("action").getString("objectKey");
        for (int i = 0; i<headers.length(); i++){
            JSONObject header = headers.getJSONObject(i);
            String name = header.getString("name").toLowerCase();
            String value = header.getString("value");
            switch (name){
                case "content-type":
                    contentType = value;
                    break;
                case "subject":
                    subject = value;
                    break;
                case "from":
                    from = value;
                    break;
                case "message-id":
                    messageId = value;
                    break;
                case "in-reply-to":
                    inReplyTo = value;
                    break;
                case "date":
                    dateParsed = value;
                    break;
            }
        }

        /*Keywords for subject filtering*/
        subjectUndeliverableKeywords.add("undeliverable");
        subjectUndeliverableKeywords.add("not authori");
        subjectUndeliverableKeywords.add("invalid number");
        subjectUndeliverableKeywords.add("error");
        subjectUndeliverableKeywords.add("not delivered");
        subjectUndeliverableKeywords.add("failure");
        subjectAutoanswerKeywords.add("automatique");
        subjectAutoanswerKeywords.add("out of office");
        subjectAutoanswerKeywords.add("automatic reply");
        subjectAutoanswerKeywords.add("automatica");
        subjectAutoanswerKeywords.add("automatische");
        subjectAutoanswerKeywords.add("autoreply");


        toForward = subjectCheckToForward()
                && contentTypeCheckToForward();

        System.out.println(toForward);
    }
    /*End of Lambda initialization*/

    /*Categorize email to send the report to SQS*/
    /*Working with HashMap 'sqsNotification' which contain email information*/
    private void sqsCategorize (){
        String category = "";
        category = getCategory();
        sqsNotification.put(sqsKeys.Category.name(), category);
        sqsNotification.put(sqsKeys.Date.name(), dateParsed);
        sqsNotification.put(sqsKeys.From.name(), from);
        sqsNotification.put(sqsKeys.Subject.name(), subject);
        sqsNotification.put(sqsKeys.InReplyTo.name(), inReplyTo);
        sqsNotification.put(sqsKeys.MessageID.name(), messageId);
        sqsNotification.put(sqsKeys.S3ObjectLink.name(), bucketName + "/" + objectKey);


        try (SqsClient sqsClient=SqsClient.builder().region(region).build()){
//            System.out.println("Check SQS creation: " + new ObjectMapper().writeValueAsString(sqsNotification));
            sqsClient.sendMessage(SendMessageRequest.builder()
                    .queueUrl(QUEUE_URL)
                                    .messageBody(new ObjectMapper().writeValueAsString(sqsNotification))
//                    .messageBody("Hello from AWS SDK for Java v2!")
                    .delaySeconds(10) // Optional parameter
                    .build());

            if (spamVerdict.toLowerCase().contains("fail")||virusVerdict.toLowerCase().contains("fail")){
                sqsClient.sendMessage(SendMessageRequest.builder()
                        .queueUrl(SPAM_QUEUE_URL)
                        .messageBody(new ObjectMapper().writeValueAsString(sqsNotification))
                        .delaySeconds(10)
                        .build());
            }

            System.out.println("Messages sent successfully.");
        } catch (Exception e) {
            System.out.println("ERROR Failed to send message: ");
            e.printStackTrace();
        }

    }
    /*End of categorize email*/

    @Override
    public String handleRequest(SNSEvent event, Context context) {

        try {
            initialize(event);
        } catch (Exception e) {
            System.out.println("ERROR: failure to initialize function");
            e.printStackTrace();
        }
        sqsCategorize();

            /*Check if message meet with forwarding criteria. Proceed with forwarding so*/
            if (toForward) {


//        System.out.println(event.toString());

                System.out.println(event.getRecords().get(0).getSNS().getMessage());

//        JSONObject parsedSNS = new JSONObject(event.getRecords().get(0).getSNS().getMessage());
//                System.out.println(parsedSNS.getJSONObject("mail").getString("messageId"));
//                String bucketName = parsedSNS.getJSONObject("receipt").getJSONObject("action").getString("bucketName");
//                String objectKey = parsedSNS.getJSONObject("receipt").getJSONObject("action").getString("objectKey");


//                from = parsedSNS.getJSONObject("mail").getJSONObject("commonHeaders").getJSONArray("from").toList().get(0).toString();

                String prependVerdicts = new String("Spam: " + spamVerdict + " \r\n" +
                        "Virus: " + virusVerdict + " \r\n" +
                        "SPF: " + spfVerdict + " \r\n" +
                        "DKIM: " + dkimVerdict + " \r\n" +
                        "DMARC: " + dmarcVerdict + " \r\n" +
                        "====================================================================\r\n");
                GetObjectRequest getObjectRequest = GetObjectRequest.builder().bucket(bucketName).key(objectKey).build();
                try (InputStream is = s3.getObject(getObjectRequest)) {
                    // Fetch email content from S3
                    byte[] emailContentBytes = prependValidationResults(is, prependVerdicts);
                    if (emailContentBytes == null) {
                        emailContentBytes = is.readAllBytes();
                    }
//            System.out.println("After Validation: " + new String(emailContentBytes));
//            String emailContent = new String(emailContentBytes, StandardCharsets.UTF_8);

//            assert emailContentBytes != null;
                    SdkBytes rawInBytes = SdkBytes.fromByteArray(emailContentBytes);

                    RawMessage rawMessage = RawMessage.builder()
                            .data(rawInBytes)
                            .build();

                    EmailContent rawContent = EmailContent.builder()
                            .raw(rawMessage)
                            .build();


                    // Forward email using SES v2
                    if (toForward) {
                        forwardEmail(rawContent, from);
                    }
                } catch (Exception e) {
                    System.out.println("ERROR in handle request");
                    e.printStackTrace();
                }
            }

            return "SQS Testing" + from;
        }

        private void forwardEmail (EmailContent emailContent, String from){

            HashSet<String> toEmail = new HashSet<>();    // Change this
//        toEmail.add("apikhtovnikov@dex.com");
//        toEmail.add("dexmailchecker-AWSSES@srv1.mail-tester.com");
            toEmail.add("jmark@dex.com");
            toEmail.add("apikhtovnikov@dex.com");
            SendEmailRequest request = SendEmailRequest.builder()
                    .content(emailContent)
                    .feedbackForwardingEmailAddress("aws_bounces@dex.com")
//                .replyToAddresses(from)
                    .fromEmailAddress(fromEmail)
                    .destination(d -> d.toAddresses(toEmail))
                    .build();
            System.out.println(request.toString());
            ses.sendEmail(request);
        }

        private Part prependValidationResultsToPart (Part part, String validationResults) throws
        IOException, MessagingException {
            System.out.println("Checking multipart");
            if (part.isMimeType("multipart/*")) {
                System.out.println("We in multipart 'if'");
                MimeMultipart multipart = (MimeMultipart) part.getContent();
                System.out.println(multipart.getCount());
                for (int i = 0; i < multipart.getCount(); i++) {
                    prependValidationResultsToPart(multipart.getBodyPart(i), validationResults);
                }
            } else if (part.isMimeType("text/plain")) {
                System.out.println("We in text/plain");
                String content = part.getContent().toString();

                part.setContent(validationResults + content, "text/plain");

            } else if (part.isMimeType("text/html")) {
                System.out.println("We in text/html");
                String content = part.getContent().toString();
                String htmpValidation = validationResults;
                htmpValidation = htmpValidation.replace("PASS", "<span style=\"color:green\">PASS</span>");
                htmpValidation = htmpValidation.replace("FAIL ", "<span style=\"color:red\">FAIL</span>");
                htmpValidation = htmpValidation.replace("GRAY", "<span style=\"color:orange\">GRAY</span>");
                htmpValidation = htmpValidation.replace("\r\n", "<br>");


                part.setContent(htmpValidation + content, "text/html");
            }

            return part;
        }

        private byte[] prependValidationResults (InputStream rawMessage, String validationResults){
            try (ByteArrayOutputStream baos = new ByteArrayOutputStream()){
                Session session = Session.getDefaultInstance(new java.util.Properties());
                MimeMessage mimeMessage = new MimeMessage(session, rawMessage);

                mimeMessage.setHeader("Return-Path", "aws_bounces@dex.com");
                mimeMessage.setSubject("[OrigFrom: " + from + " ] " + mimeMessage.getSubject());

            mimeMessage.setHeader("Reply-To", from);

                prependValidationResultsToPart(mimeMessage, validationResults);
                mimeMessage.saveChanges();


                mimeMessage.writeTo(baos);

                return baos.toByteArray();
            } catch (Exception e) {
                System.out.println("ERROR: Failed to parse raw message");
                e.printStackTrace();
            }

            System.out.println("No mime detected");
            return null;
        }

        private boolean subjectCheckToForward () {

            for (String sbj : subjectUndeliverableKeywords
            ) {
                if (subject.toLowerCase().contains(sbj)) {
                    System.out.println("Subject: " + subject);
                    System.out.println("Hit: " + sbj);
                    return false;
                }
            }


            return true;
        }
        private boolean contentTypeCheckToForward () {
            if (contentType.toLowerCase().contains("report")){
                System.out.println("Subject: " + subject);
                System.out.println("Hit: " + contentType);
                return false;
            }
        return true;
        }

        /*Categorize logic*/
        private String getCategory(){
            if (contentType.toLowerCase().contains("report")){
                if (subject.toLowerCase().contains("unsubscribe")){
                    return sqsCategories.ReportUnsubscribe.name();
                } else {
                    for (String sbj : subjectUndeliverableKeywords
                    ) {
                        if (subject.toLowerCase().contains(sbj)) {
                            return sqsCategories.ReportUndeliverable.name();
                        }
                    }
                }
            }
            for (String sbj : subjectAutoanswerKeywords
            ) {
                if (subject.toLowerCase().contains(sbj)) {
                    return sqsCategories.Autoanswer.name();
                }
            }
            if (subject.toLowerCase().contains("unsubscribe")){
                return sqsCategories.Unsubscribe.name();
            }
            if (spamVerdict.toLowerCase().contains("fail")){
                return sqsCategories.Spam.name();
            }
            if (virusVerdict.toLowerCase().contains("fail")){
                return sqsCategories.Virus.name();
            }
            if (subject.toLowerCase().contains("re:")){
                return sqsCategories.HL.name();
            }
            return sqsCategories.Other.name();
        }
    }