# PROJECTNAME

## Objective
[Brief Objective - Remove this afterwards]

The Detection Lab project aimed to establish a controlled environment for simulating and detecting cyber attacks. The primary focus was to ingest and analyze logs within a Security Information and Event Management (SIEM) system, generating test telemetry to mimic real-world attack scenarios. This hands-on experience was designed to deepen understanding of network security, attack patterns, and defensive strategies.

### Skills Learned
[Bullet Points - Remove this afterwards]

- Advanced understanding of SIEM concepts and practical application.
- Proficiency in analyzing and interpreting network logs.
- Ability to generate and recognize attack signatures and patterns.
- Enhanced knowledge of network protocols and security vulnerabilities.
- Development of critical thinking and problem-solving skills in cybersecurity.

### Tools Used
[Bullet Points - Remove this afterwards]

- Security Information and Event Management (SIEM) system for log ingestion and analysis.
- Network analysis tools (such as Wireshark) for capturing and examining network traffic.
- Telemetry generation tools to create realistic network traffic and attack scenarios.

## Steps

*Add Network Diagram Later*

Installing Virtual Box
- Step 1.1: Head to virtualbox.org and click download.<img width="975" height="732" alt="image" src="https://github.com/user-attachments/assets/6ba7d8c6-4809-418c-8994-116b06cf8868" />
- Step 1.2: Choose operating system you are using… in my case Windows.<img width="975" height="675" alt="image" src="https://github.com/user-attachments/assets/c9f65d4c-365d-43dd-af54-41dc3cb7c0d4" />
- Step 2.1: Compare Hash values to verify integrity of installer.<img width="975" height="906" alt="image" src="https://github.com/user-attachments/assets/0f182ffd-0893-4383-acbf-8eef6e6de1a7" />
- Step 2.2: Find VirtualBox version of what you downloaded inside the checksum list. In my case “VirtualBox-7.2.4-170995-Win.exe”<img width="975" height="422" alt="image" src="https://github.com/user-attachments/assets/148f0943-0642-41de-ac28-bd5876a7a5d9" />
- Step 2.3: Go to where you downloaded the file > Right Click > Then click “Open in Terminal”<img width="975" height="467" alt="image" src="https://github.com/user-attachments/assets/452e1a25-93c9-4fcd-9c72-434eac46afcc" />
- Step2.4: This will open up powershell and in powershell type command "Get-FileHash .\VirtualBox-7.2.4-170995-Win.exe" Note: “VirtualBox-7.2.4-170995-Win.exe” is my file name yours might be different. Then press enter. <img width="975" height="542" alt="image" src="https://github.com/user-attachments/assets/112c277c-68c8-4d26-a152-66c47a6ea87d" />
- Step 2.5: Double click the generated hash to copy it.<img width="975" height="547" alt="image" src="https://github.com/user-attachments/assets/fae57afd-7e1a-49f1-b003-5a439526b1fb" />
- Step 2.6: Return to virtualbox checksum list > do ctrl+F > paste in the hash value in powershell from the last step.<img width="975" height="938" alt="image" src="https://github.com/user-attachments/assets/a0aa2a7d-4c95-440c-b0d5-c22506b46f8e" />
- Step 2.7: If the same hash value shows the file is not tampered with thus verifying integrity.
- Step 3: Initialize installation.<img width="766" height="611" alt="image" src="https://github.com/user-attachments/assets/b67616de-cc53-4b30-a6ae-291ebd5dc859" /><img width="769" height="613" alt="image" src="https://github.com/user-attachments/assets/421a710f-7095-4c84-8068-533d042c6306" /><img width="761" height="617" alt="image" src="https://github.com/user-attachments/assets/63fa52d5-b508-4d0e-b1a5-3a0f7a1bb419" /><img width="755" height="622" alt="image" src="https://github.com/user-attachments/assets/b2e79757-818d-4b1e-abb9-e728643f14f3" /><img width="756" height="616" alt="image" src="https://github.com/user-attachments/assets/c38c1e8a-e38f-495d-a1d7-6ffe008ccca8" /><img width="752" height="608" alt="image" src="https://github.com/user-attachments/assets/bd7eeb66-ca32-402c-ba92-05eaba66801b" /><img width="763" height="623" alt="image" src="https://github.com/user-attachments/assets/7ee1b018-b0ef-4c9b-abb6-d7b61139bf16" /><img width="766" height="616" alt="image" src="https://github.com/user-attachments/assets/3a9a9bb0-0c08-4d66-8df8-513254db7ffd" />








 



 



  
