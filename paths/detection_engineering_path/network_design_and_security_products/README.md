# Network Design and Security Products

"Network Design and Security Products" is a comprehensive course focused on the  intricate world of network architecture and the critical role security  products play within it. This course delves into the strategic planning  and implementation of robust network infrastructures, with an emphasis  on security considerations.

Students will gain insights into the fundamentals of network design,  including network topologies, protocols, and scalability. They will also explore the latest advancements in security products, such as  firewalls, intrusion detection systems, web application firewalls (WAF), and encryption technologies. Throughout the course, students will learn to assess potential network vulnerabilities and develop strategies to  mitigate risks.

**Table of Contents:**

[Introduction to Network Design](#introduction-to-network-design)

[Network Topology Design](#network-topology-design)

[Segmentation](#segmentation)

[Network-Based Segmentation and Features](#network-based-segmentation-and-features)

[How to Implement Network-Based Segmentation?](#how-to-implement-network-based-segmentation)

[Application-Based Segmentation](#application-based-segmentation)

[Subnetting](#subnetting)

[Firewalls and Types](#firewalls-and-types)

[Network Security Products (IDS, IPS, WAF, and NAC)](#network-security-products-ids-ips-waf-and-nac)

[Network Security Products-2](#network-security-products-2)

**Evaluate Yourself with Quiz**

- [Network Design and Security Products](https://app.letsdefend.io/training/quiz/network-design-and-security-products)

## Introduction to Network Design

Designing a secure network infrastructure should be one of the most  critical tasks that should be prioritized for an organization because a  secure network infrastructure provides a secure environment and allows  the organization to use other resources efficiently. In this training,  we will explain what a secure network infrastructure is, how it should  be designed, and what themost critical points are when addressing this.  Although it is a theoretical subject, we recommend that all employees in the IT field, particularly SOC analysts, complete this training as it  covers the essential topics that are relevant in today's landscape.

Let’s start our training with the “**Network Topology Design**” topic.

## Network Topology Design

When designing a secure network infrastructure, it is a must that we  should consider both the physical and logical dimensions of network  topology. In this section, we will explore various categories of the  network topology. Before diving into these topology types, we should  mention the criterias that we should consider when determining our  optimal topology. Some of those criterias are as follows:

**Communication Requirements**

First, we need to evaluate the communication requirements of the  network. This will involve determining which devices or systems need to  communicate, how they need to communicate, and how much data needs to be transmitted. The network topology should provide the structure that  best meets these communication requirements.

**Scalability**

Future growth and expansion need of the network should be considered. The chosen network topology must not only address current demands but  also be geared towards supporting the future needs and potential expansions. Scalability simply shows the network's capacity to expand  effortlessly along with the addition of new devices or users.

**Performance and Speed**

Performance factors such as communication speed, latency, and data  transfer rate should be evaluated. The topology should ensure that  communication is fast and reliable. If the network is traffic-intensive  and requires high performance, the topology should be optimized to meet  those standards.

**Facility of Management and Maintenance**

The network topology should be designed to facilitate management and  maintenance processes. Network administrators must be able to  efficiently carry out tasks like device configuration, error monitoring, troubleshooting, and updates. Therefore, the topology should be  structured in a way that seamlessly accommodates these essential  operational processes.

**Cost**

The cost of the network topology should also be taken into  consideration. We should evaluate hardware, software, and installation  costs and provide a solution that is suitable for the budget.  Additionally, we need to assess the operating cost of the network. A  more complex topology may require more management and maintenance, which may increase the operating costs.

**Reliability and Redundancy**

Network reliability and redundancy is critically important. The  topology must ensure uninterrupted communication and minimal data loss  in the event of a single-point failure. In such scenarios, it's crucial  to incorporate redundancy and implement robust backup strategies.

**Feasibility**

Ultimately, the chosen network topology must align with the  requirements of the installation and implementation processes. It's  imperative to consider available resources, capabilities, and technical  expertise. The selected topology should also harmonize with the existing organizational infrastructure and resources.

In reality, we should note that it may not be possible to bring all  these criteria together. In fact, not all these criteria may always be  necessary. The selection of a specific topology is interconnected with  the services that will operate on the network you're designing and is  closely tied to the individual requirements of these components.

For a more concrete illustration, consider a scenario where we're  designing a network for a financial technology company that processes  thousands of transactions per second. In this context, if the potential  material and reputational losses resulting from network downtime or  slowdowns will be a lot then the network must be planned to prioritize  criteria like performance, speed, and redundancy over cost  considerations. This approach requires accepting higher costs to ensure a robust network with operational interruption.

If we are designing a network for a content-publishing service that  stores some static content, where occasional outages are not a problem,  we can then put the redundancy on the back burner and move the cost  forward.

Shortly, determining the needs correctly before starting the work,  making the projections correctly is the basis of establishing a correct  network.

Essentially, three types of network topologies are available when  designing a network architecture. You should keep in mind that these  topologies can also work together. In fact, the most important point of a well-designed and smooth-running network is the use of the right  topologies in the right place and the correct establishment of their  relations with each other.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/network-design-and-security-products/2/sni3.png)

The properties of these 3 topologies mentioned above are as follows:

### Star Topology

- Star topology is widely used in small and medium-sized networks. 
- It is often preferred in office environments, small businesses, or residential networks.
- Devices connected to the central switcher provide high-speed data transmission and facilitate network traffic management.
- In the event of a failure in one of the connected devices, the other  devices remain unaffected, so the star topology provides high  availability.
- Star topology makes it easy to add new devices or remove existing devices from the network.

### Tree Topology

- Tree topology is preferred in large-scale networks and is often used in enterprise networks.
- It creates a hierarchical structure in the form of sub-switchers connected to the main switcher and devices connected to these sub-switches.
- It is suitable for complex network structures such as large organizations or campus networks.
- The use of sub-switchers makes it easier to organize and manage network traffic.
- In case of failure of the main switcher, only the devices connected to the sub-switcher are affected, which ensures the continuity of the network.

### Full Mesh Topology

- Mesh topology is usually used in small-scale networks or special-purpose networks.
- Each device has a direct connection to all other devices on the network.
- Examples of applications include fields such as scientific research networks,  supercomputer networks, or military communications networks.
- The complete network topology ensures high-speed data transmission and low latency.
- The infrastructure cost is higher and more complex because each device is connected to every other device.

Each network topology offers advantages for different requirements  and usage scenarios. The choice of topology depends on factors such as  the size of the network, performance needs, security requirements,  budget, and number of users.

In this part of the training, we have covered the points to be  considered while designing a secure network infrastructure and network  topologies. In the next part of the training, we will learn “**Segmentation and its Types**” topic.

### Questions

1 - In the network topology design, the ability of the network to grow and expand shows which concept is applied on the network?

Note: Review the “Network Topology Design” section.

> **Answer:** Scalability

2 - What is the topology where each device is connected to every other device in the network?

> **Answer:** Full Mesh Topology

## Segmentation

Segmentation plays a crucial role in establishing a dependable  network configuration. Segmentation helps ensure security and brings a  range of advantages. It helps networks more and better manageable. For  instance, if a network with 100 endpoints and excessive traffic gets  segmented properly it will be easier to manage the network both from the traffic and the security aspect. Security vulnerabilities in one  endpoint can have cascading negative effects on others but we can easily avoid these security risks by properly segmenting these endpoints.  Segmentation will also help managing the network and it will provide us  better and easier management structure. Various segmentation methods are available as you can see below:

- Network-Based Segmentation
- Application-Based Segmentation
- Subnetting

Let’s dive into these with the “**Network-Based Segmentation**” topic in the next part of our training.

## Network-Based Segmentation and Features

Network segmentation involves partitioning the network into discrete, isolated zones. Each zone enforces distinct traffic regulations through dedicated security policies and controls. Network-based segmentation  comes with the following advantages:

**Limits the Spread of Attacks**

Segmentation acts as a barrier against the expansion of network  attacks into other sectors. In the absence of segmentation, a single  extensive network area could potentially impact the entire network in  the event of an attack. Fortunately, segmentation limits attacks to  their respective segments, averting their spread to unaffected areas.

**Reduces Insider Threats**

Segmentation plays a vital role in curbing the dissemination of  insider threats as well. For instance, if a user or device engages in  malicious activities, the impact remains limited solely to the pertinent segment. Access to resources in other segments is restricted,  effectively halting the proliferation of threats.

**Ensures Data Privacy and Isolation**

Segmentation serves as a shield for privacy by segregating different  clusters containing sensitive data from the rest. For example, having  the finance department within a distinct and isolated segment protects  unauthorized access to financial information. Furthermore, segments with distinct functions ensure regional isolation by segregating data  traffic.

**Improves Network Performance and Manageability**

Segmentation contributes to enhanced network performance and  streamlined management. Handling traffic within smaller segments  translates to simplified monitoring and improved control. Furthermore,  this approach reduces overall network traffic and minimizes conflicts,  resulting in a notable performance boost.

**Implements Security Controls and Policies**

Segmentation allows the implementation of separate security policies  in each segment which can be configured with its firewalls, network  monitoring tools, and access controls. In this way, security controls  and policies are implemented more effectively, and network  vulnerabilities are reduced.

Segmentation is one of the cornerstones of secure networking. From a  security perspective, better isolation prevents the spread of attacks  and limits access to sensitive data. In addition, it improves network  performance and simplifies management. Therefore, segmentation plays an  important role in a reliable network design.

The following items are essential steps for executing a successful segmentation of a network:

### Defining Regions and Resources in the Network

- You should divide the network into clusters and determine the  segments. This requires careful analysis of the network structure. By  identifying the servers, network devices, users, and other resources on  your network, you will have completed the basic steps for segmentation.
- It is important that you should understand the dependencies and  communication requirements between the departments or systems involved.  This allows you to accurately design segmentation by specifying the data flow and requirements.

### Assessing Security Needs

- You should fully evaluate the security requirements of each  segment. This includes security requirements such as data privacy,  integrity, authorization, authentication, and access controls.
- You must determine the levels of sensitive data between the segments and  set the security levels accordingly. Segments with critical data will  require tighter security measures and access controls.

### Defining Subnets and IP Address Ranges

- You must create a separate subnet for each segment and correctly specify the IP address ranges. This will enable traffic routing between segments and isolate traffic between segments.
- When determining the IP address ranges, you should be careful and configure the subnet masks correctly to avoid conflicts.

### Implementing Network Segmentation

- For each segment, you must configure network devices such as  gateways, routers, and firewalls. These devices route traffic between  segments and enforce security policies.
- When configuring network devices, you must set up firewall rules and access controls to suit the security needs of each segment. This will filter traffic, block harmful activity and limit access.

### Setting Access Controls and Security Policies

- You must set the access controls and security policies correctly for each segment. These include measures such as authentication,  authorization, encryption, secure login and data traffic monitoring.
- You must implement appropriate security policies and access controls to  limit access between segments. You must ensure that users and devices  can access only the required segments.

At this point, the most important thing that we always remember is  that segmentation is actually a living process and therefore it needs to be checked and improved constantly just like other security processes.  In order to achieve this, it is very important that you should  periodicize the work that we have summarized in the following five  items:

**Monitoring Traffic**

Monitoring traffic between segments is one of the most effective ways to determine if network segmentation is working correctly. Analyze data traffic between segments using network monitoring tools. If you are not seeing intersegment traffic, you can say that segmentation is active.

### **Firewall Tests**

Perform firewall tests to verify that the firewalls that limit access between segments are configured correctly. These tests simulate access  attempts from one particular segment to another and check whether there  is an unexpected transition.

### **Access Control Tests**

To assess access controls between segments, examine the capacity of  users and devices’ ability to switch between segments. You can say that  the segmentation failed if an unauthorized user or device gains access  to another segment.

### **Sensitive Data Tests**

It is important to test data security in segments that have sensitive data. Try to access sensitive data located between segments and check  if these attempts are blocked. If you gain unauthorized access to  sensitive data, you can say that segmentation is not secure.

### **Penetration Tests**

Perform penetration tests to identify weak spots between segments.  These tests simulate an attacker's attempts to attack between segments.  If an undesired transition between segments occurs, it may be an  indication that the segmentation is not working properly.

These tests will help you determine if network segmentation is  working properly. You should regularly run tests to monitor the  effectiveness of segmentation and make improvements as needed. In  addition, it is important to follow up-to-date safety standards.

We have covered the network segmentation, its importance, and its characteristics in this part of the training. In the next part, we will explore **"How to implement network-based segmentation"** topic.

### Questions

1 - What process should be applied to identify the weak points between the segments?

> **Answer:** Penetration Tests

2 - How many of the followings are true for network-based segmentation?

It helps to divide the network into isolated sub-parts.
It makes it easy to apply different security policies for different clusters.
Prevents the spread of possible successful attacks.
It is secure, but it makes it difficult to manage the network.

> **Answer:** 3

## How to Implement Network-Based Segmentation?

You can use several different approaches for network segmentation.  For example, physical segmentation is often performed using routers,  switches, and other network equipment. This is a useful way to divide a  network into several geographically distributed subnets. However, this  technique is often both expensive and complicated because the hardware  needs to be physically positioned and configured.

Physical segmentation is a type of network segmentation that usually  takes place using network hardware. Physical segmentation of a network  usually involves distributing the hardware that directs network traffic, such as routers and switches, to specific parts of the network. This  breaks up a network into smaller and more manageable chunks, while also  providing greater control and security.

Another approach is software-based segmentation. This is usually  performed using virtual networks or VLANs. VLANs are virtual networks  that run on a specific physical network and are usually configured on a  series of switches. This type of segmentation can separate network  traffic by different services, departments, or user groups.

The way VLANs (Virtual Local Area Network) work is based on a  specific protocol implemented by network devices and protocols. VLANs  are usually implemented in Layer 2 (data link layer) network switches  and these switches support VLANs by tagging Ethernet frames with VLAN  tags.

When a VLAN is created on a network switch, a unique ID is assigned  to each VLAN. This ID is usually attached to Ethernet frames using a  protocol known as 802.1Q tagging. This tag indicates which VLAN it  belongs to. When an Ethernet frame arrives at a switch port, the switch  looks at the frame's VLAN tag and decides which VLAN it belongs to.

In this way, devices in one VLAN are isolated from devices in other  VLANs because each VLAN creates a separate broadcast domain. Devices in  VLANs act as if they are in the same logical network, even though they  are in the same physical network. This allows, for example, different  departments of a company to share the same physical network  infrastructure, but logically isolated from each other.

Let's look at the example in the image below. There is a company and  the company has employees working on different floors. The systems on  each floor are connected to the switch of that floor. These switches are interconnected with the switch in the datacenter. Datacenter has a  "Finance" server and a "Devops" server. 

In cases where we do not configure any VLANs, “Accounting” and “CFO”  employees will also be able to access the “Devops” server as they are on the same network. Likewise, "Developers" will have access to the  "Finance" server. But if we move "Developer" systems and "Devops" server to VLAN No. 111, "CFO", "Accounting" employees and "Finance" server to  VLAN No. 222. Even if they are on the same physical network, they will  not be able to communicate with each other. This abstraction will be  happening on the switches.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/network-design-and-security-products/5/sni4.png)

However, when data transmission from one VLAN to another is required, a Layer 3 device (usually a router) is needed. The router must be  capable of routing data from different VLANs, this process is often  referred to as "inter-VLAN routing". This allows data to pass securely  between different VLANs, but ensures that each VLAN remains isolated  from each other.

VLANs often make network management easier and more flexible because  network administrators can group and separate specific devices  regardless of the physical location of the devices. This also improves  security because VLANs can be used to limit access to sensitive data.

We have covered how to implement network segmentation in this part of our training and will go over the “Application-Based Segmentation”  topic in the next.

## Application-Based Segmentation

Another important approach is application-based segmentation. This  method controls the traffic to certain parts of the network by dividing  network traffic using specific applications or application groups. It is usually used when it is necessary to isolate certain applications,  services, or types of data on a network. This may help enhance security  and network performance.

Application-based segmentation is usually performed using a network  security device, such as a firewall, or an Application Delivery  Controller (ADC). These devices can enforce specific network policies  tailored for particular applications or services. For instance, they can be utilized to curtail excessive network usage by a specific  application or to guarantee elevated priority for a particular  application over others.

The implementation of application-based segmentation usually involves the following steps:

**Determining the applications and services to which application-based segmentation will be applied**

If certain applications or services need to be isolated or subject to a specific network policy, you need to determine which applications or  services will be segmented.

**Installing and configuring a network security device that supports application-based segmentation**

Application-based segmentation is usually performed using a network  security device, such as a firewall or ADC. This device must implement  and enforce certain network policies for specific applications or  services.

**Defining the implementation policies and implementing them properly**

It's essential to formulate and implement distinct network policies  for every application or service. This delineates the permissible  network resources, incoming and outgoing traffic that a given  application can utilize.

**Testing and monitoring**

It is important to test the network to verify that the  application-based segmentation is configured correctly and works as  expected.

Segmentation based on applications can enhance network performance  and security, but it can introduce increased complexity in network  management. Hence, it's imperative to execute application-based  segmentation with meticulous planning.

We have covered the concept of application-based segmentation and its implementation in this part of our training. We will learn “Subnetting” in the next part.

## Subnetting

IP subnetting is a networking technique used to divide a larger IP  address space into smaller, more manageable sub-networks or subnets. It  is commonly used in IP (Internet Protocol) networks, both in local area  networks (LANs) and wide area networks (WANs), to efficiently allocate  and manage IP addresses.

Subnetting involves dividing an IP address into two parts: the  network portion and the host portion. This division is typically  represented using a subnet mask, which consists of a series of binary 1s followed by a series of binary 0s. The 1s in the subnet mask indicate  the network portion, while the 0s indicate the host portion.

Let's segment the network that we segmented with VLAN in the previous issues, this time with Subnetting. As you can see in the image below,  the "Devops" server is running on the "192.168.1.0" network and with the "255.255.255.0" subnet mask. The “Finance” server runs on the  “192.168.2.0” network and with the “255.255.255.0” subnet. In this case, we can provide an IP address to the network cards of the users (in our  example, the developers) that we want to access the "Devops" server,  from the network "192.168.1.0/255.255.255.0", so that they can access  this server.

With the same way, we can assign IP addresses to the network cards of “Accounting” users and “CFO” systems from the  “192.168.2.0/255.255.255.0” network so that they can only access the  “Finance” server.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/network-design-and-security-products/7/sni5.png)

Well, if we can do the same thing like IP Subnetting without needing any special equipment, what is the use of VLANs?

IP subnetting and VLANs are not alternatives to each other, they are  two different approaches used to segment networks. Both meet certain  requirements and in some cases are complementary to each other. However, some features of VLANs make them preferable over IP subnetting in  certain situations. Let's summarize these reasons simply:

**Flexibility**

VLANs provide a model whose network segmentation is not based on  physical location. A VLAN can contain devices anywhere in the same  physical network. For example, you can separate devices on the same  floor of a company into different VLANs or combine devices on different  floors in the same VLAN. This is flexibility that IP subnetting often  cannot offer.

**Performance and Efficiency**

VLANs limit broadcast traffic because each VLAN creates a separate  broadcast domain. This can improve the overall performance and  efficiency of the network.

**Security**

VLANs make it easy to isolate certain groups or applications from  others. This can be an important tool for limiting access to certain  network resources or data. IP subnetting can also improve security, but  VLANs often offer more flexibility in this regard.

**Network Management**

VLANs provide network administrators with the ability to more  effectively manage network traffic and resources. VLANs allow certain  parts of the network to be reconfigured as needed, which facilitates  network changes as needed.

In this part of the tutorial, we have covered “subnetting and network segmentation”. We will learn “**Firewall and its Types**” in the next part of our training.

## Firewalls and Types

### An Overview of Firewalls

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/network-design-and-security-products/8/sni11.png)

A firewall is a network security device used to protect a computer  network from potential malicious threats. It controls inbound and  outbound network traffic to ensure the security of a particular network  by creating a barrier between two networks.

Firewalls are often used to separate a company's private network  (usually a local area network or LAN) from a public network such as the  Internet. A firewall allows or blocks certain traffic from passing  through, usually by examining all traffic coming into and leaving the  network.

To do this, firewalls usually use a security policy or set of rules.  These rules determine which types of traffic will be allowed to pass and which types of traffic will be blocked. For example, a firewall may  block traffic from certain IP addresses or only allow traffic to certain types of services or applications (for example, email or web browsing).

In addition, firewalls can provide various security features. Some  can identify malicious signs like attacks or malware through network  traffic analysis. Others enable secure network connections, like VPNs  (Virtual Private Networks), ensuring remote employees connect safely to  the corporate network.

Shortly, a firewall is a critical tool for protecting the network,  blocking malicious threats, and preventing data breaches and other  security incidents.

In this section, we will discuss firewall technologies in detail.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/network-design-and-security-products/8/sni12.png)

It is possible to classify firewalls in different ways. For example,  when we classify based on their structure, it is possible to divide them into two groups as “Hardware” and “Software”. If we are to classify  them according to their location, we can again divide them into two  groups; “Network-Based” and “Host-Based”. 

The most common of these classifications is the perspective, in which they are classified according to the OSI layers they support. Let's  take a look at the types of firewalls with this approach:

### Layer 3 (Network Layer) Firewalls (Packet Filtering Firewall)

Network layer firewalls operate at layer 3 of the OSI model and  control network traffic based on IP addresses. Such firewalls filter  traffic by examining IP-level information such as source IP address,  destination IP address, protocol type, and port numbers using packet  filtering methods. They are often used in gateways or routers.

A Layer 3 firewall is usually located at the Network Layer, which is  responsible for routing and forwarding data packets in a network. Such  firewalls control traffic based on IP addresses, protocols, and other  layer 3 information. Layer 3 firewalls are typically used to filter both inbound and outbound traffic.

Layer 3 firewalls control traffic in a number of different ways.  Typically, techniques such as network address translation (NAT), port  address translation (PAT) are used.

NAT and PAT manage the traffic in and out of the network while hiding the IP addresses and ports of the devices on the network. This not only makes it harder for people outside the network to discover the network, but also helps to streamline network traffic.

Layer 3 firewalls are generally stateless. This means that they treat each packet as an independent unit, and they usually decide based on  the packet's source or destination IP address, protocol, or ports. These decisions are usually based on a set of predetermined rules.

### Layer 4 (Transport Layer) Firewalls (Stateful Inspection Firewall)

Transport layer firewalls operate at layer 4 of the OSI model and are based on transport layer protocols such as TCP (Transmission Control  Protocol) and UDP (User Datagram Protocol). Such firewalls analyze  network traffic based on source and destination port numbers, link  state, and transport protocol. They can monitor traffic by doing due  diligence and filter according to security policies.

The Layer 4 (Layer 4) firewall is located in the Transport Layer,  which controls the transport of data packets in the network. These  firewalls decide on the source and destination IP addresses of the  packets as well as the TCP or UDP ports used. They can usually examine  network traffic at a deeper level and control the flow of data over a  particular port whether a particular application is using it or not.

Layer 4 firewalls are often used to filter both inbound and outbound  traffic. They are quite important for protecting and controlling a  network. It is especially critical to block malicious traffic and  regulate the flow of data on the network.

These types of firewalls are also often referred to as stateful  because they can keep track of a "session" or "connection" state. That  is, they can monitor all stages of a packet's journey over the network  and make decisions accordingly. This provides more sophisticated  security because these firewalls can take into account the past activity of a particular session or connection.

This stateful control goes a step further than Layer 3 firewall  because it also takes into account general traffic patterns and  connection states on the network, rather than relying solely on  individual characteristics of packets.

Especially in a network with sensitive or private information, such a control mechanism can be an important tool for providing enhanced  network security.

### Layer 7 (Application Layer) Firewalls (Application Level Firewall)

Application layer firewalls operate at the 7th layer of the OSI model and analyze application-level protocols and data communications.

The Layer 7 firewall is located in the Application Layer, which is  the top layer of the network model. Such firewalls can usually do a much deeper data inspection. They analyze incoming traffic over application  protocols such as HTTP, HTTPS, FTP, DNS.

Layer 7 firewalls have the ability to determine what type of data a  particular application or service can send and receive. For example, it  can examine and control incoming HTTP or HTTPS requests to a web  application or service. This way, they can only allow certain types of  requests while blocking other types of requests.

In addition, such firewalls can often analyze the traffic patterns of a particular application or service and detect abnormal or suspicious  activity. This provides extra protection, especially against  sophisticated threats such as denial of service (DoS) attacks or  application level attacks.

Layer 7 firewalls typically provide much more visibility and control  over what's going on at the application layer of a network. This is  crucial to improve network security and better manage potential threats. However, properly configuring and managing this type of firewall is  often more complex and requires more technical knowledge.

The order we gave above actually also refers to the historical  development of firewall devices. At the point reached today,  manufacturers are adding more features to their products every day due  to both consumer needs and marketing strategies. For this reason, almost all of the products marketed today support Layer 7, in addition to  these, they promise a very effective protection not only based on rules  and signatures, but also with the support of machine learning,  artificial intelligence technologies and real-time threat intelligence.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/network-design-and-security-products/8/sni6.png)

### Cloud Based Firewall

With the development of cloud technologies, the "... as a service"  business model, the concept of cloud based firewall has inevitably  entered our lives. Cloud Based Firewalls are firewalls that technically  have all the features of L7 firewalls, but that you purchase as a  service, not a product.

One of the biggest advantages of cloud-based firewalls is scalability and flexibility. You can easily access more capacity or reduce capacity when you need it. In this way, the amount you will pay is shaped  according to your needs. So, the amount of payment also varies,  depending largely on how much you need.

Another advantage of cloud-based firewalls is that they are usually  faster and easier to update. To quickly provide protection against new  threats and zero-day attacks, the firewall must be up-to-date at all  times. Cloud-based services usually implement such updates  automatically, ensuring that your network is constantly protected  against the most up-to-date threats.

As a result, cloud-based firewalls offer greater scalability,  flexibility, and ease of use compared to traditional firewalls, while  also offering advanced security features and the ability to update  quickly. However, it is important to remember that trust in cloud  services and the reliability of the cloud provider are vital to the  success of this type of security solution.

In this part of the training, we have covered firewalls and its types. In the next part, we will learn about “**Network Security Products (IDS, IPS, WAF and NAC)**”.

### Questions

1 - At which OSI Layer does the Stateful Firewall operate?

> **Answer:** 4

2 - How many of the followings are the functions of the firewall? 

 \- Protecting the network
 \- Blocking threats
 \- Preventing data breaches
 \- Generating logs of the network traffic
 \- Storing e-mails

> **Answer:** 4

## Network Security Products (IDS, IPS, WAF, and NAC)

### Intrusion Detection Systems(IDS)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/network-design-and-security-products/9/sni14.png)

Intrusion Detection Systems(IDS) are quite interesting and complex  tools. In fact, you can think of it like a guardian of a network.

IDSs generally monitor and examine network traffic continuously. For  this they are usually placed at the core of a network where they monitor all data packets to and from the internet or other parts of your  network. They act as an observer to make sure everything is going right  and no one is harming your network.

IDSs detect potential threats, often using a number of different  methods. There are two main types of IDS: “Anomaly-based IDS” and  “Signature-based IDS”.

**Anomaly-based IDS**

This kind of IDS learns the typical data traffic patterns within your network and notifies you in the presence of anomalies. For instance, if a user notices that their regular data downloads are minimal and  suddenly witnesses a significant surge in download activity, they might  suspect an attack and trigger an alert. However, it's important to  acknowledge that such IDS systems could potentially generate false  positives—incorrectly identifying regular harmless activities as  threats.

**Signature-based IDS**

Such IDs use the "signatures" or patterns of known attacks. That is,  they describe previously known harmful behaviors and attack techniques.  This is similar to how virus scanning software searches for a specific  signature of a virus. While such IDS systems can frequently demonstrate  high accuracy, their capability is limited to identifying threats that  have been documented before. Detecting novel and unknown attacks can  prove challenging for them.

**Behavior-based IDS**

Behavior-based IDS determines normal and abnormal behavior patterns  by analyzing data such as network traffic, system activities, and user  behavior. The system has a predefined set of behavioral rules or  algorithms, and these rules are used to detect unusual or potentially  dangerous behavior in the system.

This type of IDS, unlike signature-based IDS, uses techniques such as statistical analysis, artificial intelligence, or machine learning to  identify anomalies or behavioral deviations, rather than relying on  known threat signatures. As a result, the potential to identify  unfamiliar or specifically targeted attacks might be enhanced.

Furthermore, contemporary IDS products can also operate with data  feeds obtained from real-time threat intelligence sources, enhancing  their functionality through **reputation-based** analysis.

Finally, it should be noted that hybrid products that have adopted  more than one of these approaches are also available in the market. 

IDS products typically function by analyzing a mirrored copy of  network traffic, as they solely observe without taking any direct  actions. This approach offers the advantage of not impeding real-time  network traffic speed, as the examination occurs without direct  interaction. Additionally, this method facilitates the utilization of a  more extensive range of rules. However, this operational mode's drawback is its retrospective nature, it detects events after their occurrence.  When properly scaled to the traffic volume under examination, this delay within a suitably configured IDS device is typically measured in  seconds.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/network-design-and-security-products/9/sni7.png)

IDs are often used as part of a network security strategy and often work in harmony with other security tools and systems.

### Intrusion Prevention Systems(IPS)

IDs and IPS share commonalities as both oversee network traffic to  identify potential threats. However, IPS, or Intrusion Prevention  System, takes it a step further, not only detecting but also aiming to  stop or minimize attacks.

Understanding an IPS requires examining its network connection. It's  usually positioned on the network's core, the vital data pathways. Here, it continually monitors and regulates traffic. Unlike IDS, IPS is  positioned inline, meaning traffic enters the IPS device first. After  analyzing the traffic, if it deems it malicious, it stops the traffic;  if not, it lets the traffic through. This approach's notable drawback is the risk of network delays, leading to a more restrained ruleset  compared to IDS.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/network-design-and-security-products/9/sni8.png)


When an IPS detects a particular attack pattern or signature, it  can automatically trigger a sequence of responses. These typically  include actions like blocking malicious packets, rerouting harmful  traffic, or even intentionally slowing down the network to impede  malicious activity.

Additionally, an IPS might endeavor to pinpoint the source of the  attacks and isolate it from the network. This safeguards against  internal threats or attacks stemming from within the network.

The specific actions undertaken by an IPS are generally configured by the system administrator or security team. IPS systems are usually  highly customizable, allowing adjustments to align with network needs  and specific requirements.

For effective operation, an IPS requires continual updates and  maintenance. Regular updates to the threat signature database are  crucial to guard against recognized threats. Additionally, to counter  new and unknown threats, IPS can often leverage advanced detection  methods like behavioral analysis.

In summary, IPS acts as a proactive sentinel. Beyond just identifying potential network threats, it tries to prevent or minimize their  impact. This proactive defense is pivotal for reinforcing network  security, yet for an IPS to yield optimal results, it necessitates  accurate configuration and consistent updates.

### Web Application Firewall (WAF)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/network-design-and-security-products/9/sni13.png)

Web application firewalls are tailored to counter threats against web applications. They are normally positioned in front of a web  application, they regulate all incoming HTTP/HTTPS traffic. These  systems scrutinize incoming requests and assess them against a  predefined rule set to determine if the request poses a threat or is  benign.

The fundamental premise of a WAF lies in addressing the inherent  vulnerabilities often faced by web applications. Attacks like "SQL  Injection" and "Cross-Site Scripting (XSS)" serve as common techniques  to compromise web application security.

A WAF offers specialized safeguarding against such vulnerabilities.  Traditional firewalls may not inherently shield against these risks as  they primarily manage lower-level network traffic. However, a WAF is  uniquely focused on the content of HTTP/HTTPS traffic, enabling it to  pinpoint application-level threats.

For instance, a WAF can check an HTTP request to ascertain if it  corresponds to a "SQL Injection" attempt. In case of a match, the  request is blocked, effectively stopping the attack.

Similarly, a WAF can also identify a "Cross-Site Scripting (XSS)"  attack. In such cases, attackers aim to embed malicious scripts into a  web application. The WAF identifies and neutralizes this type of threat.

WAFs are typically adaptable and can be tailored to align with the  distinct needs and vulnerabilities of your web application. Rules can be consistently updated to ensure protection against evolving threats.

In essence, WAFs constitute a specialized firewall variant  meticulously crafted to safeguard web applications. As such, they hold  immense significance for web-centric enterprises and services. They are  often used in conjunction with other security measures and are an  important part of a network security strategy.

WAF products can be situated on-premises or obtained as cloud-based services, offering flexibility in implementation.

### Network Access Control (NAC)

Network Access Control serves as a security solution aimed at  regulating network access and defining activities permitted within the  network. Essentially, NAC governs inbound and outbound network traffic  based on specific guidelines. These guidelines typically factor in user  credentials, device attributes, schedules, and at times, even the user's physical location.

At its core, NAC operates on the premise that all network users are  not equivalent. Some users necessitate access to specific resources,  while others require restricted privileges. Similarly, a user's network  interactions might be confined to certain timeframes or geographic  locations. NAC functions to enforce such policies, ensuring controlled  and tailored network access.

A NAC system usually consists of several components:

**Authentication**

NAC uses authentication methods to verify a user's identity and their entitlement to network access. This typically involves utilizing  details like a username and password, or occasionally a hardware ID.

**Device Control**

NAC may perform a device audit to ensure that devices connected to  the network are secure and have up-to-date security patches. If device  security is not sufficient, NAC may limit or block access.

**Policy Management**

NAC is used to manage and implement network policies, with policy  management standing as a cornerstone of its functionality. These  policies determine network access privileges, device permissions, and  authorized activities. For instance, they might define that a specific  user category can access designated network resources or that a certain  device type is permitted network connection.

In this section of the training, we have covered IDS, IPS, WAF, and  NAC concepts as part of network security. we will keep learning about  the Network Security Products in the next chapter.

### Questions

1 - What is the system that is usually positioned inline?

> **Answer:** 4

## Network Security Products-2

Products such as Firewall, IDS, IPS WAF, NAC, which we talked about  in the previous topics, are indispensable technologies and products to  securely control a network. But today, these products alone may not be  enough to prevent all risks. For this reason, it is important that they  are supported by technologies such as EDR/XDR, PAM, Email Gateway, and  Sandbox. Since these products are not directly related to network  security, we do not go into details in this section, but it would be  useful to briefly take a look at what they are to get an idea:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/network-design-and-security-products/10/sni15.png)

### Endpoint Detection and Response (EDR)

Endpoint Detection and Response provides continuous monitoring of  devices (computers, mobile devices, servers, etc.) connected to a  network and detection of potential threats on these devices. An EDR  system usually monitors what each device is doing. If it detects an  anomaly in the behavior of a device, it can immediately issue a warning  or even stop a certain process.

EDR systems often protect against many different types of threats,  including malware, zero-day attacks, and even more sophisticated and  advanced threats.

### Extended Detection and Response (XDR)

XDR extends the capabilities of EDR and enables greater integration  and automation between various security products. XDR systems often  include EDR as well as network monitoring, cloud security, email  security, and other security components.

The main advantage of XDR is its ability to detect and respond to  threats, often in a broader context. This usually automatically  consolidates and analyzes security alerts and events. This helps  security teams respond to threats faster and more effectively.

Both systems are important tools used to strengthen organizations'  defenses against cyber threats. Which system to use often depends on an  organization's specific needs and resources.

### Data Loss Protection (DLP)

The main purpose of DLP systems is to ensure that organizations  comply with various regulations and to prevent incorrect sharing of  sensitive and private data. These regulations may often relate to the  privacy of personal data, the security of financial information, or  intellectual property rights.

To understand how a DLP system works, we can think of a security  check at an airport. If you find something in your luggage that you are  not allowed to take with you, security will ask you to remove it. DLP  works the same way; prevents certain types of information from leaving  the network.

### Virtual Private Network (VPN)

In essence, a VPN creates a secure tunnel over the internet,  encrypting your data and giving you private and anonymous access to the  internet. This tunnel protects all your internet traffic, preventing  your data from being tracked or intercepted by third parties.

First off, VPNs increase data security. Organizations often work with sensitive and proprietary information (customer information, financial  data, employee records and more). VPNs encrypt internet traffic to  prevent this information from being tracked or intercepted by third  parties. This helps prevent data from falling into the wrong hands,  especially if employees are using unsecured networks such as public  Wi-Fi networks.

Second, VPNs support remote work. During and after the pandemic, many employees began working from home or other remote locations. VPNs allow these employees to securely access the organization's network. This  allows employees to do their jobs securely from anywhere.

Third, VPNs allow bypassing geo-restrictions. Some websites or  services may not be accessible to users in certain regions. VPNs allow a user to circumvent these restrictions by passing their internet traffic through a different location. This can help organizations do business  in certain markets or access certain resources.

Finally, VPNs can help organizations comply with regulations. Certain industries have specific regulations on data security, particularly in  areas where sensitive information is common, such as healthcare and  finance. VPNs can provide an additional layer of security to comply with these regulations.

**Remote Access VPN**

This type is usually used by those who work from home or are on a  travel. A Remote Access VPN allows the user to securely access a private network remotely.

**Site-to-Site VPN**

Site-to-Site VPN is often used by large organizations that have  offices in multiple physical locations. Site-to-Site VPN creates a  secure network connection between different locations so all locations  work like one private network.

### SIEM (Security Information and Event Management)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/network-design-and-security-products/10/sni16.png)

Up to this point, we have known the security tools that can be used  to build a secure and sustainable network. But we also have to say that  building the network is not where the work ends, but where it actually  begins. Continuous, real-time monitoring and evaluation of events are  required for a network to remain secure.

All the products, network devices and operating systems we have been  talking about so far as in our working environment are systems that  generate logs constantly and store them. When necessary, we can go to  each of these products and examine these logs one by one. But if we're  running a large organization, that means millions of rows of data at  thousands of points, and it's not manageable to go through and review  all these logs. In addition, in many of these systems, the log storage  capacity is very limited and access to historical logs is often not  possible.

The answer of the companies that produce solutions for the sector has been SIEM products. 

SIEM stands for Security Information and Event Management. These  systems are often used to monitor, detect and respond to security  incidents in large-scale IT environments.

SIEMs are a type of surveillance system that combines and analyzes  all security-related information on an organization's network. These can include log files and other types of data from network devices,  servers, applications, and even users' workstations. The SIEM system  receives and analyzes this data, detects deviations from normal, and  generates alerts when necessary.

The way a SIEM works usually depends on the specific requirements and configuration of the organization. But usually, they include the main  components such as data collection, event correlation, alert generation, and reporting.

**Data collection**

SIEM usually collects security-related data from a large number of  different sources on the network. This usually includes log files, but  it can also include network traffic analysis, user behavior analysis,  and more.

**Correlation**

SIEM often brings together a large number of different events and  analyzes them in a broad context. This makes it possible to determine  whether an event is part of a single negative event.

**Creating an alert**

If the SIEM detects a deviation from the normal or a possible safety  event, it usually generates an alert. This allows the security team to  respond quickly to the incident.

**Reporting**

Finally, SIEM usually provides an overall picture of the security  situation. This is usually done with detailed reports containing various graphs, tables, and other visual elements.

SIEMs have many advantages for organizations. The most obvious  advantage is perhaps the rapid detection and response of a security  incident. A SIEM can often detect a security incident much faster, which can significantly reduce the organization's response time to the  incident.

SIEMs are also important for regulatory compliance. In most  industries, organizations are required to comply with certain security  standards, and SIEMs provide the extensive records and reports needed to establish and demonstrate compliance with these requirements.

Finally, a SIEM often provides an overview of an organization's  security status. This makes it easy for the security team to understand  the overall security situation and make strategic changes as needed.  Therefore, a SIEM can be an important part of an organization's overall  security strategy.

### Security Orchestration, Automation and Response (SOAR)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/network-design-and-security-products/10/sni17.png)

Security Orchestration, Automation, and Response (SOAR) consists of a set of technologies that help improve and automate an organization's  capabilities to respond to security threats.

SOAR platforms integrate with a number of different security  technologies, including SIEM, and "orchestrate" them to work together.  This allows organizations to combine multiple threat detection resources and create a broader security outlook.

Perhaps the most important feature of SOAR is its ability to automate security operations. This can speed up the processes of responding to  simple threats and provides security teams with the opportunity to focus on more complex and urgent threats. SOAR can also increase its ability  to respond more quickly to security incidents by speeding up threat  detection and response processes.

SOAR platforms also include creating response scenarios, or  "playbooks," to streamline the process of responding to threats. This  automates and standardizes the steps to be followed when a security  incident is detected.

There are several advantages that SOAR offers for organizations:

**Productivity**

SOAR empowers security teams to counter threats quickly and  efficiently, resulting in expedited threat resolution and minimized  potential damages.

**More visibility**

SOAR provides an overview of the security posture of an organization. This allows security threats to be managed more effectively.

**Automation**

SOAR can automate the threat detection and response processes. This means faster response times and less manual intervention.

**Risk reduction**

SOAR can reduce the overall risk by ensuring that a security incident is handled quickly and effectively.

Shortly, SOAR can enhance and automate an organization's security  operations, which often means faster threat detection and response times and overall more effective security situation management.

### Questions

1 - How many of the following are the benefits of VPN? 

 \- Providing a secure tunnel
 \- Removing geoblocks
 \- Making websites load faster
 \- Facilitating compliance with regulations
 \- Facilitating user access

> **Answer:** 4

2 - How many of the following operations can be performed with SIEM?

 \- Applying correlations between logs
 \- Analyzing suspicious files
 \- Resetting weak user passwords
 \- Restarting network devices

> **Answer:** 1



