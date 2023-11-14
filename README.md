# OWASP_test_381

## [Live](http://18.208.185.108:8080/FileUploadApp_war/)


## Security Report for OWASP_test_381
### Prepared by: Asadbek Karimov

**Summary:**
	The security assessment of the FileUploadServelet in OWASP_test_381 application highlights potential security vulnerabilities, mainly related to file uploads. These vulnerabilities may allow for the execution of malicious code and denial of service attacks.

**Scope:**
	The assessment focuses on the FileUploadServlet, specifically on its file upload functionality.

## Findings:
**Vulnerability 1:** Lack of Content Validation and Filename Sanitization
The application does not perform content validation on uploaded files, making it susceptible to malicious file uploads. Attackers may upload files with malicious content, potentially executing code on the server or affecting other users.
Not Validating specific file types, nested file types, or trusting client  Content-Type header can result in saving malicious files in the server.

```
Example:  
Maliciousfile.exe
// nested file types (Double extensions)
Maliciousfile.exe.jpg
```


The application violates OWASP foundation guidelines for file extension checks. Additionally, filename sanitization is absent, allowing all uploaded files to be saved with their original filenames. This is dangerous as it may lead to system instability, exploit vulnerabilities, or trigger unexpected behavior.

The line <kbd>part.write(uploadFilePath + File.separator + fileName);</kbd> is potentially susceptible to path traversal attacks if an attacker manipulates the filename parameter in the request.

Example:
```java 
The "uploads" directory is not directly accessible from the web however with the above-stated file type validation an attacker can upload 
Maliciousfile.jar

Then the attacker can manipulate the filename parameter to traverse the file system.
../../uploads/Maliciousfile.jar
```

And then with another upload, he can execute the same file and thus compromise the system. 


Vulnerability 2:  Lack of DDoS Mitigation
The application does not implement proper rate limiting or any DDoS mitigation techniques. This exposes the application to the risk of being overwhelmed by a large number of requests, potentially leading to a denial of service situation.

Example:  I use the Chrome developer tools to try to capture the request when uploading the file and then I create a simple script to replay that request over and over to see if the web server will stop me after my x number of tries.



Then I created a basic bash script that generates a form-data type image generates random binary data as content and a random file name and then repeatedly sends it to the endpoint. 


Here’s the bash script created to achieve this.
```sh
#!/bin/bash

num_requests=50

# Base URL
base_url='http://localhost:3001/FileUploadApp_war_exploded/FileUploadServlet'

# Loop to send requests
for ((i = 1; i <= num_requests; i++)); do
  # Generate a random number for the file name
  random_number=$(shuf -i 1-100000 -n 1)

  # Create a temporary file with random content
  echo "Random Content $random_number" > "temp_file_${random_number}.webp"

  # Send the file using curl
  curl -F "fileName=@temp_file_${random_number}.webp" "$base_url"

  # Clean up the temporary file
  rm "temp_file_${random_number}.webp"

done
```



	
**Recommended  Fixes:**
## Vulnerability 1: Content Validation and Filename Sanitization
To fix this first before writing the uploaded files to the server, it’s crucial to validate their content to prevent potential security risks. One common approach is to check the file’s content type (MIME type) to ensure that it matches the expected types.
Content Validation
List<String> allowedContentTypes = Arrays.asList("image/jpeg", "image/png", "image/gif", "image/bmp");

// get the uploaded file type
String contentType = part.getContentType();

// Check the content type of the uploaded file
if (!allowedContentTypes.contains(contentType)) {
   response.getWriter().write("Invalid file type.");
   return; }


To fix the issue with filenames, we can assume users can be malicious, leading to directory traversal attacks or another security issue. To mitigate this I added an extra step where the filename gets sanitized before saving it on the server using regex.

**Filename Sanitization**
```java
// Sanitize the filename to remove harmful characters
fileName = fileName.replaceAll("[^a-zA-Z0-9.-]", "_");
```
This code replaces any characters that are not letters, digits, periods, or hyphens with underscores.

### Vulnerability 2: DDoS Mitigation
To address the DDoS vulnerability we can take some steps to protect our service by filtering, rerouting traffic, and dropping connecting from susceptible IP addresses on the different layers of the OSI layer.
 		
Application layer we can implement rate limiting and request validation and also have new rules set up on the application firewall to filter traffic and block requests.
	
We can also implement more robust rate-limiting strategies by implementing a load balancer to reroute traffic between our ec2 instance if we have the ability to scale our ec2 instance. Most easiest solution for a DDoS attack can be to scale our service vertically or horizontally to handle the traffic.
```java
// Rate limiting
private static final Map<String, Integer> requestCounts = new ConcurrentHashMap<>(); 
private static final int MAX_REQUESTS = 10; // max request allowed in time frame
private static final long TIME_FRAME_MILLIS = 60000; // 1 minute

// Rate limiting 
String clientIP = request.getRemoteAddr();
if (!allowRequest(clientIP)) { 
    response.getWriter().write("Request limit exceeded."); return; 
}
// utility function
private boolean allowRequest(String clientIP) {
        long currentTime = System.currentTimeMillis();
        requestCounts.putIfAbsent(clientIP, 0);
 
        // Remove outdated records
        requestCounts.entrySet().removeIf(entry -> (currentTime - entry.getValue()) > TIME_FRAME_MILLIS);
 
        int currentCount = requestCounts.get(clientIP);
 
        if (currentCount < MAX_REQUESTS) {
            requestCounts.put(clientIP, currentCount + 1);
            return true;
        } else {
            return false; // Request limit exceeded
        }
    }

```


This is a basic rate limiting mechanism using an in-memory map to keep track of request counts from different clients using a hash map for quick look-up. To make it more secure we can implement a security framework that comes with rate limiting built into it however the idea is the same. 

### Conclusion:
In summary, the security assessment of the OWASP_test_381 application has revealed two critical vulnerabilities. The first concerns content validation and filename sanitization, which could lead to malicious file uploads and security breaches. The second vulnerability is the absence of DDoS mitigation measures, making the application susceptible to denial of service attacks.

To address these issues I have implemented fixes to the original code such as implemented content validation by checking file content types and sanitizing filenames to prevent security risks. Apply rate limiting, request validation, and firewall rules at the application layer to mitigate DDoS threats.

### Resources 
- [Tomcat Server Docs](https://tomcat.apache.org/tomcat-8.5-doc/index.html)
- [OWASP Web Application Testing](https://github.com/OWASP/wstg/tree/master/document/4-Web_Application_Security_Testing)
- [Setting up AWS Security Group](https://stackoverflow.com/questions/31208834/what-port-tomcat7-use-how-do-i-set-aws-security-group)
