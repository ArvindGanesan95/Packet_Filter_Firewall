package com.packetfilter;

import java.io.*;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.util.*;

// A type to represent a Firewall, which can accept/deny packets based on rules
public class Firewall {

      String rulesFile;
      HashMap<String,List<PortsAndIP>> rulesMap;
      static String fileName="fw.csv";

      Firewall(String filePath) throws IOException {
            //Check if file exists
            if(!new File(filePath).exists()) return;
            rulesMap= new HashMap<>();
            rulesFile=filePath;
            // load the data from the given rules file
            loadDataFromFile(rulesFile);
    }

      // Function to load rules from the file, create a hashmap
      void loadDataFromFile(String rulesFile) throws IOException {
          try{
              BufferedReader br = new BufferedReader(new FileReader(rulesFile));
              String line;
              while ((line = br.readLine()) != null) {
                  String[] fields = line.split(",");
                  String trafficDirection=fields[0].trim();
                  String trafficProtocol=fields[1].trim();
                  String portValue=fields[2];
                  String ipAddressValue=fields[3].trim();
                  String key=trafficDirection+trafficProtocol;
                  if(rulesMap.containsKey(key)){
                      PortsAndIP result=insertPortAndIPAddress(portValue,ipAddressValue);
                      ArrayList<PortsAndIP> existingData= (ArrayList<PortsAndIP>) rulesMap.get(trafficDirection+trafficProtocol);
                      existingData.add(result);
                      rulesMap.put(trafficDirection + trafficProtocol,existingData);
                  }
                  else {
                      ArrayList<PortsAndIP> data= new ArrayList<PortsAndIP>();
                      PortsAndIP result=insertPortAndIPAddress(portValue,ipAddressValue);
                      if(result!=null) {
                          data.add(result);
                          rulesMap.put(trafficDirection + trafficProtocol,data);
                      }
                  }
              }

          }
          catch (Exception error){
            System.out.println("Exception thrown: "+error.getMessage());
          }
      }

      // Function to check port and IP address for contraints and return class  object
      PortsAndIP insertPortAndIPAddress(String portValue,String ipAddressValue) throws UnknownHostException {
          if(portValue==null || portValue=="" || ipAddressValue==null || ipAddressValue=="") return null;
          PortsAndIP portipObject = null;
          // Check if a port is given as a range
          if(portValue.split("-").length==2){
              String[] portValueArray=portValue.split("-");
              int startingPort=  Integer.parseInt(portValueArray[0]);
              int endingPort  =  Integer.parseInt(portValueArray[1]);
              int portRange=endingPort-startingPort;
              if(checkForValidity(portValueArray[0],"PORT") && checkForValidity(portValueArray[1],"PORT")) {
                  if(portipObject==null) portipObject = new PortsAndIP();
                  portipObject.startingPort=startingPort;
                  portipObject.endingPort=endingPort;
              }
              else return portipObject;
          }
          else {
              int startingPort=  Integer.parseInt(portValue.split("-")[0]);
              if(checkForValidity(portValue,"PORT")) {
                  if(portipObject==null) portipObject = new PortsAndIP();
                  portipObject.startingPort=startingPort;
                  portipObject.endingPort=startingPort;
              }
              else return portipObject;
          }
          // Check if an ip is given as a range
          if(ipAddressValue.split("-").length==2){
              String startingIP=ipAddressValue.split("-")[0];
              String endingIP=ipAddressValue.split("-")[1];

              if(checkForValidity(ipAddressValue.split("-")[0],"IP") && checkForValidity(ipAddressValue.split("-")[1],"IP")) {
                  portipObject.startingIP=InetAddress.getByName(startingIP);
                  portipObject.endingIP=InetAddress.getByName(endingIP);
              }
              else return null;
          }
          else {

              if(checkForValidity(ipAddressValue,"IP")) {
                  portipObject.startingIP=InetAddress.getByName(ipAddressValue);
                  portipObject.endingIP=InetAddress.getByName(ipAddressValue);
              }
              else return null;
          }
          return portipObject;
      }

      // Function to check if PORT or IP satisfies its constraints
      boolean checkForValidity(String input, String type){
          boolean result=false;
          if(input=="" || input==null) return false;
          switch (type){

              case "PORT": {
                  int port=Integer.parseInt(input);
                  //Check port range
                  result = port>=1 && port<=65535;
                  break;
              }

              case "IP":{

                  String[] ip=input.split("\\.");
                  boolean isValidIP=true;
                  // Check if each octet is within the range
                  for(int index=0;index<ip.length;index++){
                      if(!(Integer.parseInt(ip[index])>=0 && Integer.parseInt(ip[index])<=255)){
                          isValidIP=false;
                      }
                  }
                  result = isValidIP;
                  break;
              }
          }
          return result;
      }

      //Function to check if an input packet can be accepted or denied. This function, gets the list
      //associated with input direction and protocol and checks the ip range for the matching port object.
      boolean accept_packet(String direction,String protocol,int port,String ip_address) throws UnknownHostException {
          try{

              if(direction==null || protocol==null || port<1 || port>65535 || ip_address==null) return false;

              if(direction.equals("inbound") || direction.equals("outbound")){
                  if(protocol.equals("tcp") || protocol.equals("udp")){
                      if(checkForValidity(Integer.toString(port),"PORT")
                              && (checkForValidity(ip_address,"IP"))){

                          // if hashmap is not initialized, return. Most like due to file not present in the path as given
                          // in the constructor
                          if(rulesMap==null) return false;
                          List<PortsAndIP> data= rulesMap.getOrDefault(direction+protocol,null);

                          if(data==null) return false;
                          //Iterate through the list and check each ip range for each port
                          for (PortsAndIP targetObject : data) {
                              if (targetObject.startingPort <= port && targetObject.endingPort >= port) {

                                  // Check if the ip ranges contain the input ip_address
                                  if (compareAddresses(targetObject.startingIP, targetObject.endingIP, ip_address)) {
                                      return true;
                                  }
                              }
                          }

                          return false;
                      }
                      else {
                          return false;
                      }
                  }
                  else return false;
              }
              else return false;
          }

          catch (Exception error){
            System.out.println("Exception : "+error.getMessage());
          }
          return false;
      }

      // Function to compare ip addresses
      // Source: https://stackoverflow.com/a/4256603/7937993
      boolean compareAddresses(InetAddress startingIP,InetAddress endingIP,String ipAddress) throws UnknownHostException {
          if(startingIP==null || endingIP==null || ipAddress.equals("") || ipAddress==null) return false;
          byte[] octet1=startingIP.getAddress();
          byte[] octet2=endingIP.getAddress();
          byte[] octet3=InetAddress.getByName(ipAddress).getAddress();
          long result1=0,result2=0,result3=0;
          for(byte octet:octet1){
              result1=result1<<8;
              result1|=octet & 0xff;
          }
          for(byte octet:octet2){
              result2=result2<<8;
              result2|=octet & 0xff;
          }
          for(byte octet:octet3){
              result3=result3<<8;
              result3|=octet & 0xff;
          }
          return (result3>=result1 && result3<=result2);
      }

      public static void main(String[] args) throws IOException {

          try {
              // get current working directory path
              String cwd = new File("").getAbsolutePath();
              Path path = FileSystems.getDefault().getPath("").toAbsolutePath();
              // Create file path
              String filePath=path.toString()+"/"+fileName;
              Firewall fw= new Firewall(filePath);
              boolean test1 = fw.accept_packet("inbound", "tcp", 80, "192.168.1.2");
              boolean test2 = fw.accept_packet("inbound", "tcp", 53, "192.168.2.1");
              boolean test3 = fw.accept_packet("outbound", "tcp", 1234, "192.168.10.11");
              boolean test4 = fw.accept_packet("outbound", "tcp", 71, "192.168.1.2");
              boolean test5 = fw.accept_packet("inbound", "udp", 234, "52.12.48.92");
              boolean test6 = fw.accept_packet("inbound", "udp",377,"192.45.56.85");
              boolean test7 = fw.accept_packet("outbound", "udp",825,"123.45.56.78");
              boolean test8 = fw.accept_packet("outbound", "udp",670,"123.45.56.85");
              boolean test9 = fw.accept_packet("outbound", "tcp",999,"52.12.48.92");
              boolean test10 = fw.accept_packet("outbound", "tcp",500,"52.12.48.92");
              System.out.println(test1);
              System.out.println(test2);
              System.out.println(test3);
              System.out.println(test4);
              System.out.println(test5);
              System.out.println(test6);
              System.out.println(test7);
              System.out.println(test8);
              System.out.println(test9);
              System.out.println(test10);


          }
          catch (Exception error){
            System.out.println("Exception thrown: "+error.getMessage());
          }
      }

}


//  A type to represent Port and List of IP addresses
class PortsAndIP{

      int startingPort;
      int endingPort;
      InetAddress startingIP;
      InetAddress endingIP;

      PortsAndIP(){

      }

     PortsAndIP(int startingPort,int endingPort,InetAddress startingIP,InetAddress endingIP){
       this.startingPort=startingPort;
       this.endingPort=endingPort;
       this.startingIP=startingIP;
       this.endingIP=endingIP;
     }
}





