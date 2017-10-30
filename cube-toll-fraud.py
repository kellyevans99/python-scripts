#!/usr/bin/env ptyhon
"""
This program checks the conifiguration of all Cintas router's to ensure
they are not easily suspeptible to toll fraud issues
.

"""
import paramiko
import time
import smtplib
import logging


def commands(connection, command_list):
    """
    send and recieve commands to network devices.
    returns output from the commands in command list
    """
    output = ""
    error = False
    while not error:
        i = 2
        for command in command_list:
            if i % 2 == 0:
                # wait for command in output
                if command == "":
                    pass
                else:
                    output += wait_until(command, connection)
                    if output.find("Timeout!!!!") != -1:
                        error = True
                        break
                i += 1
            else:
                # send command
                connection.send(command + "\n")
                i += 1
        return output

def wait_until(aStr, connection, timeout=10):
    
    """
    After a command is sent, read the output and wait until the string
    (aStr) is found in the output.
    
    returns a string
    
    """
    
    i = 0
    strOutput = ""
    isFound = False
    byteOutput = b''
    while i <= timeout:
        # recieve up to 5,000 bytes of info from the device
        try:
            byteOutput = connection.recv(5000)
        except:
            pass
        # convert the byte output to a string
        strOutput += str(byteOutput, "utf-8")
        # look for aStr in strOutput, if found within the timeout, stop the search
        if strOutput.find(aStr) > -1:
            isFound = True
            break
        else:
            i += 0.5
            time.sleep(0.5)
    if isFound:
        return strOutput
    else:
        return strOutput + "Timeout!!!!"

def send_email(body):
    
    #send results via e-mail
    gmail_user = "SprintMVS@gmail.com"
    gmail_pwd = "P@radis3"
    FROM = "SprintMVS@gmail.com"
    TO = ["kelly.m.evans@sprint.com"]
    SUBJECT = "Cintas Router report"
    TEXT = body
    
    # Prepare actual message
    message = """From: %s\nTo: %s\nSubject: %s\n\n%s""" % (FROM, ", ".join(TO), SUBJECT, TEXT)
    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.ehlo()
        server.starttls()
        server.login(gmail_user, gmail_pwd)
        server.sendmail(FROM, TO, message)
        server.close()
        logging.info("The email was sent.")
        return True
    except Exception as e:
        logging.info('There was an error sending the email:')
        logging.info(e)
        return False

if __name__ == "__main__":
    # global variables
    t0 = time.time()
    argon = '199.11.1.160'
    neon = "199.11.1.150"
    userID = "kelevans"
    userPass = "Nic0le2@more"
    connection_error = False

    # setup logging
    logging.basicConfig(filename='/tmp/Cintas.log',
                                   filemode='a',
                                   format='%(asctime)s - %(levelname)s - %(message)s',
                                   level=logging.INFO)
    logging.info('##############################################################')
    logging.info('###########  Starting Script #################################')
    logging.info('##############################################################')

    # ssh instance
    logging.info('Connecting to argon')
    ssh_conn = paramiko.SSHClient()
    ssh_conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # connect to device via ssh
    try:
        ssh_conn.connect(argon,username=userID,password=userPass)
        logging.info("Connected to argon.")
    except:
        logging.info("Couldn't connect to argon.  Trying neon.")
        try:
            ssh_conn.connect(neon,username=userID,password=userPass)
            logging.info("Connected to neon.")
        except:
            logging.info("Couldn't connect to neon.")
            connection_error = True

    if not connection_error:
        time.sleep(1)    
        # create interactive session
        ssh = ssh_conn.invoke_shell()
        # set timeout
        ssh.settimeout(.5)
    
        # set commands to send to equipment (This will list all of the devices)
        command_list = ["%>", "msdomain cnts.mrn", "%>"]
        ssh_output = commands(ssh, command_list)
        print('ssh output\n')
        # parse the output and grab just the routers in the DNS entries.  Routers get put in the router_list.
        logging.info("Getting the list of routers.")
        router_list = []
        ssh_output_list = ssh_output.split("\r\n")
        print(ssh_output_list)
        for line in ssh_output_list:
            temp_List = line.split(" ")
            for item in temp_List:
                if "rtr" in item:
                    if "\t" in item:
                        item_List = item.split("\t")
                        item_List[0] = item_List[0][:-1]
                        router_list.append(item_List[0])
                    else:
                        item = item[:-1]
                        router_list.append(item)
                break
        # check each router in router_list, then put the results in the dictonary
       # status as router : [connected, public interface, voip router, corrected]
        status = {}
        print('router list\n')
        print(router_list)
        for rtr in router_list:
            logging.info("Looking at " + rtr)
            connected = False
            public = False
            voice_router = False
            fixed = False
            command_list = ["",
                                       "ssh " + rtr,
                                       "Password:",
                                       userPass,
                                       "#",
                                       "term len 0",
                                       "#",
                                       "show ip int brie",
                                       "#",
                                       "show run | inc dial-peer",
                                       "#",
                                       "show run | sec voice service voip",
                                       "#",
                                       "logout",
                                       "%>"]
            ssh_output = commands(ssh, command_list)
            if ("Couldn't connect." not in ssh_output and "Timeout!!!!" not in ssh_output):
                connected = True
                output_list = ssh_output.split("\r\n")
                ip_list = []
                for line in output_list:
                    temp_list = line.split(" ")
                    for item in temp_list:
                        if item.count(".") == 3:
                            if ("63.167.73" not in item and "199.11" not in item and "199.160" not in item and "199.161" not in item and "199.162" not in item):
                                ip_list.append([temp_list[0], item])
                                break
                for interface in ip_list:
                    if (interface[1][:3] != "10." and interface[1][:7] != "192.168"):
                        public = True
                        break
                if "dial-peer voice" in ssh_output:
                    voice_router = True
                if ("no ip address trusted authenticate" not in ssh_output and "ip address trusted list" in ssh_output):
                    fixed = True
            status[rtr] = [connected, public, voice_router, fixed]
            logging.info(str(status[rtr]))

        # closing the ssh session
        logging.info('Closing the ssh session')
        ssh.close()

       # prepare the body of the email
        logging.info('Preparing the email.')
        body = ""
        count = 0
        bad_routers = []
        bad_count = 0
        for router in status:
            if (status[router][0] == True and status[router][1] == True and status[router][2] == True and status[router][3] == False):
                body = body + router + "\n"
                count += 1
            if status[router][0] == False:
                bad_routers.append(router)
                bad_count += 1
        if count > 0:
            body = "Routers that need attention:\n" + body
        else:
            body = "There are no routers that need attention this week.\n"

        if bad_count > 0:
            body = body + "\nRouters that had a connectivity problem:\n"
            for router in bad_routers:
                body = body + router + "\n"
        else:
            body = body + "\nThere were no routers that had a connectivity problem.\n"

        t1 = time.time()
        runtime = t1-t0
        body = body + "\nThe runtime was " + str(runtime) + " seconds.\n"

        # send email
        logging.info('Sending email.')
        send_email(body)
        logging.info("This is the body of the email:")
        logging.info(body)
    else:
        body = "Couldn't connect to argon or neon.  No routers were scanned."
        send_email(body)
        logging.info("This is the body of the email:")
        logging.info(body)

    logging.info('Script is done.')
