# Shiina42-Bot: Personal Assistant
IRC-Based Polyfunctional Bot written in Python 2.7

### Dependencies:
- [socks.py](https://github.com/Anorov/PySocks/blob/master/socks.py)
- [tweepy](https://github.com/tweepy/tweepy) `# pip2.7 install tweepy`
- [imgurpython](https://github.com/Imgur/imgurpython) `# pip2.7 install imgurpython`

### TODO:
- [x] Clean code
- [x] Checksum validation at startup
- [x] Tor Support `tor-enabled` in shiina42.cfg
- [ ] Implement `*-enabled = "NO"` configuration
- [x] Hook into Twitter API
	- [x] Manage Twitter DMs (user controlled)
	- [ ] Automatic DM replies
	- [x] Implement tweet fetching (`.gt <[@]user>` command)
	- [x] Hashtag scrobbling
		- [ ] ...and parsing
- [ ] Custom proxy support
- [x] Configure DAT file through IRC chat
- [x] Hook into ImgurAPI
	- [ ] Upload images
	- [ ] Search for images by keyword
	- [ ] Compare images (pattern recognition)
		- [ ] Deduce keywords
- [ ] Hook into Reddit API
- [ ] Hook into Google Callendar
- [x] Look into Translation APIs
	- * Google Translate API is not free, therefore not an option
	- * Bing Translate API is very limited, but free plan exists
	- [ ] Implement Bing Translate API
	- [ ] Set user limitation for using translate functions
- [ ] Make Shiina42 do stuff autonomously
