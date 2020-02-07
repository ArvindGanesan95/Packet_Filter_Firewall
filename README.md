# ILLUMIO CODING CHALLENGE

By,
**Arvind Ganesan**


  
### Used Tools and Frameworks
 - **IDE:** IntelliJ Ultimate 2019.2.3
 - **Java Version:** Java 8 SDK
   
## Working of Code
   - The program loads the csv and creates a hashmap of the form:                       HashMap<String,List<PortsAndIP>>
    - where the key=traffic direction + traffic protocol. Ideally, there are only 4 combination of key values possible, namely, "inboundtcp","inboundudp","outboundtcp","outboundudp". 
    - The Value is a List of PortsAndIP Class. PortsAndIP Class holds starting and ending ports, list of ip addresses.
    - When an input packet comes, the corresponding key is chosen in O(1) time using direction and protocol. Then the value as a List is iterated for K elements in the list. For every element in the list, if the input IP address falls within the range is checked. So, assume one key has N-1 elements and the other key has 1 element. So , Time Complexity : O(N-1)~O(N)
    - Final Complexity: O(N) [forming hashmap] + O(N) [Querying and returning result]



## Future Work
 - I thought of reducing the time to search a port based on the input. 
   I tried applying the concept of merging overlapping intervals to reduce search complexity. 
   But the complexity was greater than linear search, where merging required sorting the intervals first.
   -  I also thought of storing port ranges as an interval tree would help us in efficient lookup of port and ip address in O(logN) time.
   -  Add JUnit framework to test the application
   -Try to create a decision tree
    
## Edge Cases Covered
-   If input file is null or empty, the program is returned.
-   If any of the parameters in each of the functions are either null or "", it's returned instantly.
-   If input file does not exist, program returns from the function instantly
-   If a key does not exist in hashmap, it means the rule is not present in         csv.So if value of hashmap is null, false is returned
-   A try/catch clause is added to handle exceptions
-   Hashmap is initialized once file exists. If its not and accept_packet function is       called, hashmap.get throws nullpointer exception. So null case is handled.


## INTERESTED TEAMS
-   Platform Team (Priority 1) 
-   Policy Team (Priority 2)
-   Data Team (Priority 3)

    



