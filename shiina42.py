#!/usr/bin/env python2

# AUTHOR: Kagami95 (https://github.com/Kagami95)
# @v_sha512 'cd4f2fb4aacf1366859e95a1d9c3bcd6d8465a2a3815b31034f38fed2501816b3929610d88640e124f5f16f89608b27ec2b41027120b600e24a73ff50a612550'

import time, socket, os, ssl, socks, hashlib, re, select, tweepy
from datetime import datetime
from imgurpython import ImgurClient

# General Variables
bot_name = 'shiina42'
debug_enabled = True
data_map = {}
config_options = {}
default_config = [ '# Shiina42 is a polyfunctional bot developped by Kagami95. http://github.com/Kagami95\n\n', '\n# General Configuration\n' 'creator = ""\n', 'tor_enabled = "NO"\n', '\n# IRC Configuration\n', 'irc_enabled = "YES"\n', 'irc_server = ""\n', 'irc_port = 6697\n', 'irc_channel = "#"\n', 'irc_nickname = ""\n', 'irc_password = ""\n', '\n# Twitter Configuration\n', 'twitter_enabled = "NO"\n', 'twitter_DM_interval = 60000\n' 'twitter_ckey = ""\n', 'twitter_secret = ""\n', 'twitter_atoken = ""\n', 'twitter_atoken_secret = ""\n', '\n# Imgur Configuration\n', 'imgur_enabled = "NO"\n', 'imgur_id = ""\n', 'imgur_secret = ""\n']

# IRC-Bot Variables
mail_list = {}
connected = False
closing = False
timeout = 0
irc_socket = None

# Twitter-Bot Variables
last_DM_check = 0

# Imgur-Bot Variables
imgur_client = None

# Checksum Validation
def validate_checksum(debug):
	hasher = hashlib.sha512()
	with open(os.path.realpath(__file__), 'r') as f:
		contents = f.read()
		bad_line = ''
		checksum = ''
		for line in contents.split('\x0a'):
			if '@v_sha512' in line.replace(' ', ''):
				bad_line = line
				break
		for substring in bad_line.replace('@v_sha512', '').split():
			test = re.sub('[^0-9a-fA-F]+', '', substring)
			if len(test) == 128:
				checksum = test
		hasher.update(contents.replace(bad_line+"\n", ''))
		digest = hasher.digest().encode('hex')
		if debug:
			print 'Expected  ', checksum
			print 'Calculated', digest
		if digest == checksum:
			return 1
		else:
			return 0


##############################################
####                                      ####
###         START LOGGING FUNCTIONS        ###
####                                      ####
##############################################

# Pretty Debug Formatting
def format(data):
	template = "[@DATE @HEXTIME][@BOTNAME@@SERVER] @DATA"
	return template.replace('@BOTNAME', config_options['irc_nickname']).replace('@SERVER', '%s/%s' % (config_options['irc_server'], config_options['irc_port'])).replace('@DATE', time.strftime('%d/%m/%y')).replace('@HEXTIME', hextime()).replace('@TIME', time.strftime('%H:%M:%S')).replace('@DATA', data)

# Prints if debug is enabled
def debug(data, log):
	if debug_enabled:
		print format(data)
		if log:
			log(data)

# Logs data to file
def log(data):
	with open("%s.log" % (bot_name), "a") as f:
		f.write(format(data))

##############################################
####                                      ####
###         END LOGGING FUNCTIONS          ###
###         START SETUP FUNCTIONS          ###
####                                      ####
##############################################

# Runs startup functions
def init():
	new_config = create_config()
	if new_config[0]:
		print '{0}\'s configuration files were created. Be sure to review them before relaunching!'.format(bot_name)
		file_names = ''
		for file in new_config[1:]:
			file_names += file + ' '
		print 'Files to review: ' + file_names
		exit()
	load_config()
	load_mail()
	load_data()
	auth_imgur()
	auth_twitter()

# Creates a configuration file if it doesn't already exist
def create_config():
	info = [False]
	if not os.path.exists(bot_name + '.cfg'):
		info[0] = True
		info.append(bot_name + '.cfg')
		with open('%s.cfg' % bot_name, 'w') as file:
			file.writelines(default_config)
	if not os.path.exists(bot_name + '.dat'):
#		info[0] = True
		# info.append(bot_name + '.dat')
		with open('%s.dat' % bot_name, 'w') as file:
			data_map = {'twitter_subs': {}, 'last_twitter_DM' : 0}
			file.write(str(data_map))
	if not os.path.exists(bot_name + '.mail'):
#		info[0] = True
		# info.append(bot_name + '.mail')
		with open('%s.mail' % bot_name, 'w') as file:
			file.write('{}')
	return info

# Parses the configuration file
def load_config():
	file = open('%s.cfg' % (bot_name), 'r')
	for line in file:
		try:
			if len(line) <= 1 or line[0] == '#':
				continue
			options = line.replace('"', '').replace('\n', '').split(' = ')
			config_options.update({options[0] : options[1]})
			print ('Set %s to %s' % (options[0], options[1]))
		except:
			print ("Something went wrong when setting the %s variable from the configuration file") % (line)
			continue

# Parses the data file
def load_data():
	global data_map
	if not os.path.exists('%s.dat' % (bot_name)):
		return
	with open('%s.dat' % (bot_name)) as f:
		data_map = eval(f.read())

# Authenticates with Imgur
def auth_imgur():
	global imgur_client
	imgur_client = ImgurClient(config_options['imgur_id'], config_options['imgur_secret'])

# Authenticates with Twitter
def auth_twitter():
	global twitter_api
	auth = tweepy.OAuthHandler(config_options['twitter_ckey'], config_options['twitter_secret'])
	auth.set_access_token(config_options['twitter_atoken'], config_options['twitter_atoken_secret'])
	twitter_api = tweepy.API(auth)

# Connects to IRC server
def connect():
	global irc_socket
	irc_server = config_options['irc_server']
	irc_port = int(config_options['irc_port'])
	irc_password = config_options['irc_password']
	irc_channel = config_options['irc_channel']
	irc_nickname = config_options['irc_nickname']

	debug('Connecting to %s:%s...' % (config_options['irc_server'], config_options['irc_port']), log)
	irc_socket.connect ((irc_server, irc_port))
	irc_socket = ssl.wrap_socket(irc_socket, ssl_version=ssl.PROTOCOL_TLSv1, ciphers="ALL")

	irc_socket.send('NICK %s\r\n' % (irc_nickname))
	irc_socket.send ('USER %s %s %s :IRC Bot\r\n' % (irc_nickname, irc_nickname, irc_nickname))

	irc_socket.setblocking(0)


##############################################
####                                      ####
###         END SETUP FUNCTIONS            ###
###         START UTIL FUNCTIONS           ###
####                                      ####
##############################################

# Returns Base16 time-stamp
def hextime():
	now = datetime.now()
	secs=(now - now.replace(hour=0, minute=0, second=0, microsecond=0)).total_seconds() * 0.75851
	mins=secs/16
	secs=secs%16
	hours=mins/256
	mins=mins%256
	return '#%s%s%s' % (hex(int(hours))[2:].upper(), hex(int(mins))[2:].zfill(2).upper(), hex(int(secs))[2:].upper())

# Formats a number into an ordinal
def format_ordinal(index):
	ordinal = str(index) + 'th'
	if str(index)[-1] == '1':
		ordinal = str(index) + 'st'
	elif str(index)[-1] == '2':
		ordinal = str(index) + 'nd'
	elif str(index)[-1] == '3':
		ordinal = str(index) + 'rd'
	return ordinal

# Checks if a certain IRC handle has been recorded as an Operator
def is_op(handle):
	if handle == config_options['creator']:
		return True
	with open('%s_ops.txt' % (bot_name), 'r') as file:
		for line in file:
			if line.replace('\n', '') == handle:
				return True
	return False

# Strips string of all non-alphanumeric characters (except 0x0A), returns lowercase
def simplify(string):
	simple = ''
	for c in string:
		if c.isalpha() or c.isdigit() or c == '\n':
			simple += c
	return simple.lower()

# Parses mail file (raw dictionary)
def load_mail():
	global mail_list
	if not os.path.exists('%s.mail' % (bot_name)):
		save_mail()
	with open('%s.mail' % (bot_name), 'r') as f:
		mail_list = eval(f.read())

# Writes mail dictionary to a file
def save_mail():
	global mail_list
	with open('%s.mail' % (bot_name), 'w') as f:
		f.write(str(mail_list))

# Writes data map to a file
def save_data():
	global data_map
	with open('%s.dat' % (bot_name), 'w') as f:
		f.write(str(data_map))

# Fetches latest tweet by user
def get_tweet(user, index):
	tweet = twitter_api.user_timeline(screen_name = user, count = index)
	# print str(tweet)
	return tweet[index-1]

# Fetches latest DM on twitter
def get_last_DM():
	dm = twitter_api.direct_messages(since_id=data_map['last_twitter_DM'])
	# direct_messages = tweepy.Cursor(api.direct_messages, since_id=0).items()
	# dm = direct_messages[0]
	return dm
	# return [dm.sender_screen_name, dm.text]

# Handles new DMs
def check_DM(sender):
	try:
		if not 'last_twitter_DM' in data_map:
			data_map.append({'last_twitter_DM' : 0})
		dm = get_last_DM()[::-1]
		for msg in dm:
			chat(sender, "DM from @%s: %s" % (msg.sender_screen_name.encode('utf-8'), msg.text.encode('utf-8')))
			debug("DM from @%s: %s (%s)" % (msg.sender_screen_name.encode('utf-8'), msg.text.encode('utf-8'), msg.id), False)
			data_map['last_twitter_DM'] = msg.id
			save_data()
		return (len(dm) > 0)
	except:
		debug("DM Fetch Failed", True)
		return False

# Sends PRIVMSG to channel (can be a single handle), splitting the message every 255 characters.
def chat(channel, msg):
	try:
		if channel == "$root":
			channel == config_options['creator']
		array = []
		x = 0
		while len(msg) > 0:
			array.append(msg[:255])
			x+=255
			msg = msg[x:]

		for line in array:
			cmd = 'PRIVMSG %s :%s\r\n' % (channel, line)
			irc_socket.send(cmd)
	except:
		None

##############################################
####                                      ####
###           END UTIL FUNCTIONS           ###
###         START COMMAND FUNCTIONS        ###
####                                      ####
##############################################

# Sends a new mail from sender to recipient
def new_mail(sender, recipient, message):
	global mail_list
	if recipient == '$root':
		recipient = config_options['creator']
	inbox = []
	if recipient in mail_list:
		inbox = mail_list[recipient]
	inbox.append([sender, message])
	mail_list.update({recipient : inbox})
	save_mail()

# Retrieves messages for sender (deletes messages once read)
def read_mail(sender):
	if sender in mail_list:
		res = "You have 1 new message:"
		if len(mail_list[sender]) != 1:
			res = "You have %d new messages:" % (len(mail_list[sender]))
		for mail in mail_list[sender]:
			res += "%s: %s" % (mail[0], mail[1])
		del mail_list[sender]
		save_mail()
		return res
	return "You have no new messages!"

def send_DM(sender, rcpt, message):
	try:
		res = twitter_api.send_direct_message(screen_name=rcpt, text=message)
		chat(sender, "Message sent!")
	except Exception, ex:
		print 'ex: ' + str(ex[0][0]['code'])
		if ex[0][0]['code'] == 150:
			chat(sender, "You can only DM people who follow you!")

# Parses a command, making decisions
def parse_cmd(sender, destination, message):
	global closing
	debug("Command from %s: %s" % (sender, message), False)
	try:
		message = message.replace('\r\n', '')
		if simplify(message) == 'help': # ".help"
			send_help_dialogue(sender)
		if simplify(message) == 'ping': # ".ping"
			chat(sender, 'Pong')
		elif simplify(message)[:5] == 'inbox': # ".inbox"
			chat(read_mail(sender))
		elif simplify(message)[:4] == 'send' or simplify(message)[:4] == 'mail': # ".send", ".mail"
			if len(simplify(message)) == 4:
				chat(sender, 'Aliases: [send, mail]; Usage: send <handle> <message>')
				return
			new_mail(sender, message.split(' ')[1], message[4+3+len(message.split(' ')[1]):])
			chat(sender, 'Your message will be relayed to %s the next time they run the .inbox command!' % (message.split(' ')[1]))
		elif simplify(message)[:2] == 'gt':
			if len(message.split()) == 2:
				username = message.split()[1].replace('@', '')
				print username
				tweet = get_tweet(username, 1)
				if tweet == None:
					chat(sender, "Tweet not found!")
				chat(sender, "Latest tweet by @%s: %s" % (username, tweet.text.encode('utf-8')))
			elif len(message.split()) == 3:
				username = message.split()[1].replace('@', '')
				index = int(message.split()[2])
				if index < 1:
					chat(sender, "Usage: gt <username> [index >= 1]")
					return
				tweet = get_tweet(username, index)
				if tweet == None:
					chat(sender, "Tweet not found!")
				ordinal = format_ordinal(index)
				chat(sender, "%s most recent tweet by @%s: %s" % (ordinal, username, tweet.text.encode('utf-8')))
		elif simplify(message) == 'tf': # ".tf" twitter feed
			get_twitter_feed(sender)
		elif simplify(message)[:2] == 'tf': # Missed previous conditional, therefore has arguments
			args = message.split()[1:]
			update_tf_config(sender, args)
		elif simplify(message)[:2] == 'dm': # ".dm" Direct Message (Twitter)
			if is_op(sender):
				if simplify(message) == "dm":
					if not check_DM(sender):
						chat(sender, "No New Messages")
				elif len(message.split()) < 3:
					chat(sender, "Usage: dm <recipient> <message>")
				else:
					recipient = message.split()[1]
					text = ''.join(message[2+2+len(recipient):])
					send_DM(sender, recipient, text)
			else:
				chat(sender, 'You don\'t have permission to access DMs!')
		elif simplify(message) == 'reboot': # ".reboot"
			if is_op(sender.replace('@', '')):
				irc_socket.send('QUIT\r\n')
				closing = True
				exit()
			else:
				chat(sender, 'You don\'t have access to that command!')
		else:
			return

	except Exception, ex:
		chat(sender, 'Error! :(')
		print str(ex)

# Sends help dialogue to sender
def send_help_dialogue(sender):
	chat(sender, 'Here is a list of what I can do:')
	time.sleep(0.25)
	chat(sender, '--Passive Functions--')
	time.sleep(0.25)
	chat(sender, '    Automatic inbox relaying on joining main channel')
	time.sleep(0.25)
	chat(sender, '--Active Functions--')
	time.sleep(0.25)
	chat(sender, '    .ping               - I will respond with "Pong" if I am online.')
	time.sleep(0.25)
	chat(sender, '    .tf                 - I will compose and send you your twitter feed as defined in the configuration file.')
	time.sleep(0.25)
	chat(sender, '    .tf <[@]user> <i>.. - For each <user> provided, I will set the .tf command to pull <i> tweets from them. Configuration is saved.')
	time.sleep(0.25)
	chat(sender, '    .gt <[@]user> [i]   - I will send you <username>\'s <i>th latest tweet.')
	time.sleep(0.25)
	chat(sender, '    .mail <nick> <msg>  - I will relay <message> to <handle> the next time they join our channel or run .inbox.')
	time.sleep(0.25)
	chat(sender, '    .inbox              - I will reply with any messages mailed to you since the last .inbox execution.')
	time.sleep(0.25)
	chat(sender, '--Bot Operators Only--')
	time.sleep(0.25)
	chat(sender, '    .reboot             - I will disconnect and reconnect to IRC.')
	time.sleep(0.25)
	chat(sender, '    .dm                 - I will read out my newest twitter DMs.')
	time.sleep(0.25)
	chat(sender, '    .dm <[@]user> <msg> - I will send <username> a twitter DM.')

# Retrieves tweets from various users
def get_twitter_feed(sender):
	global data_map
	for info in data_map['twitter_subs'][sender]:
		username = info[0]
		index = info[1]
		while index > 0:
			msg = "@%s's %s most recent tweet: " % (username, format_ordinal(index))
			try:
				tweet = get_tweet(username, index)
				chat(sender, msg + tweet.text.encode('utf-8'))
			except:
				chat(sender, "FAILED to get @%s's %s most recent tweet!" % (username, format_ordinal(index)))
			index -= 1
			time.sleep(0.2)

# Sets the provided arguments under the sender's twitter feed configuration
def update_tf_config(sender, args):
	array = []
	for index in range(len(args)):
		if index % 2 == 1: # Odd number, to skip <i> (see send_help_dialogue())
			continue
		array.append([args[index].replace('@', ''), int(args[index+1])]) # Append [user, i]
	data_map['twitter_subs'].update({sender : array})
	save_data()
	chat(sender, 'Your configuration has been updated. Run .tf to try!')

##############################################
####                                      ####
###         END COMMAND FUNCTIONS          ###
###         START EXEC FUNCTIONS           ###
####                                      ####
##############################################

def loop():
	global connected, timeout, data_map, last_DM_check, closing
	signal = select.select([irc_socket], [], [], 10.0)
	millis = int(round(time.time() * 1000))
	if connected and (last_DM_check + int(config_options['twitter_DM_interval'])) <= millis:
		last_DM_check = millis
		check_DM(config_options['creator'])
	if signal[0]:
		data = irc_socket.recv(4096)
	else:
		timeout += 1
		if timeout >= 34:
			irc_socket.send('QUIT\r\n')
			debug("No Pings Received: REBOOT", True)
			closing = True
			exit()
		return
	timeout = 0
	if len(data) > 0:
		debug(data.decode('utf-8'), False)
	if data.find('PING') != -1:
		cmd = 'PONG ' + data.split()[1] + '\r\n'
		debug(cmd, False)
		irc_socket.send (cmd)
	if not connected and data.find("MODE ") != -1:
		connected = True
		if len(config_options['irc_password']) != 0:
			chat('NickServ', 'IDENTIFY %s' % (config_options['irc_password']))
		irc_socket.send('JOIN %s\r\n' % (config_options['irc_channel']))
		debug("Connected!", False)
		last_DM_check = millis
		return
	if not connected:
		return
	if data.find('JOIN ') != -1:
		sender = (str(data)[1:].split('!')[0])
		chat(sender, read_mail(sender))
		return
	try:
		sender = (str(data)[1:].split('!')[0])
		destination = (str(data)).split('PRIVMSG')[1].split(' :')[0]
		message = (str(data)).split('PRIVMSG ')[1].split(' :')[1]
	except:
		return
	if message[0] == '.':
		parse_cmd(sender, destination, message)
	elif '\x66\x75\x63\x6B\x20\x79\x6F\x75' in message.lower():
		chat(sender, "No thanks, I don't want Herpes.") # Sassy Bot


def run():
	if not validate_checksum(True):
		print "Invalid Checksum! Quitting..."
		exit(1)
	print "Checksum Validation Succeeded"
	global irc_socket, closing
	init()
	if config_options['tor_enabled'] == 'YES':
		socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", 9050, True)
		socket.socket = socks.socksocket
	irc_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	while True:
		res = os.system("ping -c 1 %s" % (config_options['irc_server']))
		if res == 0:
			break
	connect()
	while True:
		try:
			if(closing):
				break
			loop()
		except (KeyboardInterrupt, SystemExit):
			break
		except:
			continue

##############################################
####                                      ####
###          END EXEC FUNCTIONS            ###
###         START FUNCTION CALLS           ###
####                                      ####
##############################################

run()

## BELOW ARE TESTING CALLS.
# auth_twitter()
# for tweet in twitter_api.search(q='Shiina42_TR'): # Finds every tweet containing #Shiina42_TR
	# print tweet.text
