"""Training data for the SheShield threat classifier.

HONEST DESCRIPTION: this is a hand-written, template-based dataset authored for this project.
It is NOT a corpus of real victim messages. Every example comes from a template with slot
fillers (amounts, sites, times). Templates, not individual sentences, are the unit used for
splitting, so a test sentence never shares a template with a training sentence.

Hindi and Kannada text should be reviewed by native speakers before any real-world use.

Classes merge some of the requested categories because of data size:
  cyberstalking_contact    = cyberstalking + repeated unwanted contact
  coercive_manipulation    = coercive control + isolation + emotional manipulation
"""
import itertools
import random

CLASSES = ["benign", "harassment_abuse", "cyberstalking_contact", "sextortion", "blackmail_extortion",
           "threat", "impersonation", "romance_scam", "financial_scam", "phishing", "coercive_manipulation"]
LANGS = ["en", "hinglish", "hi", "kn", "kanglish"]

FILL = {
    "en": dict(media=["photos", "pics", "videos", "nudes", "private chat screenshots"],
               amt=["5000", "10000", "20000", "50k"],
               site=["instagram", "facebook", "whatsapp groups", "porn sites", "your college group"],
               time=["tonight", "in one hour", "by 6 pm", "tomorrow morning"],
               person=["your family", "your parents", "your boss", "your friends", "everyone you know"]),
    "hinglish": dict(media=["photos", "videos", "nude pics", "chat ke screenshots"],
                     amt=["5000", "10 hazaar", "20k", "50000 rupay"],
                     site=["instagram", "facebook", "whatsapp groups", "porn sites"],
                     time=["aaj raat tak", "1 ghante mein", "kal subah tak"],
                     person=["tere ghar walon", "tere parents", "tere boss", "sabko"]),
    "hi": dict(media=["फोटो", "वीडियो", "प्राइवेट तस्वीरें"],
               amt=["5000", "10 हज़ार", "20,000"],
               site=["इंस्टाग्राम", "फेसबुक", "व्हाट्सऐप ग्रुप"],
               time=["आज रात तक", "एक घंटे में", "कल सुबह तक"],
               person=["तेरे घरवालों", "तेरे माँ-बाप", "सबको"]),
    "kn": dict(media=["ಫೋಟೋ", "ವಿಡಿಯೋ", "ಖಾಸಗಿ ಚಿತ್ರಗಳು"],
               amt=["5000", "10 ಸಾವಿರ", "20000"],
               site=["ಇನ್‌ಸ್ಟಾಗ್ರಾಮ್", "ಫೇಸ್‌ಬುಕ್", "ವಾಟ್ಸಾಪ್ ಗ್ರೂಪ್"],
               time=["ಇವತ್ತು ರಾತ್ರಿ", "ಒಂದು ಗಂಟೆಯಲ್ಲಿ", "ನಾಳೆ ಬೆಳಿಗ್ಗೆ"],
               person=["ನಿನ್ನ ಮನೆಯವರಿಗೆ", "ನಿನ್ನ ಅಪ್ಪ ಅಮ್ಮನಿಗೆ", "ಎಲ್ಲರಿಗೂ"]),
    "kanglish": dict(media=["photos", "videos", "private pics"],
                     amt=["5000", "10 saavira", "20000"],
                     site=["instagram", "facebook", "whatsapp group"],
                     time=["ivattu raathri", "ond ghante olage", "naale beligge"],
                     person=["ninna mane avarige", "ninna appa ammanige", "ellarigu"]),
}

T = {
 "sextortion": {
  "en": ["send {amt} rupees or i will post your {media} on {site}",
         "i have your nude {media}. pay {amt} {time} or {person} will see them",
         "if you don't send me more {media} i will leak the ones i have",
         "i recorded our video call. transfer {amt} or it goes viral {time}",
         "your private {media} are with me. block me and they go to {person}"],
  "hinglish": ["{amt} bhej warna tere {media} {site} pe daal dunga",
               "mere paas tere nude {media} hain, {time} paise de nahi to {person} ko bhej dunga",
               "aur {media} bhej nahi to jo hain wo sab viral kar dunga",
               "video call record kar li hai maine, {amt} de varna viral",
               "block kiya to tere {media} {person} ko mil jayenge"],
  "hi": ["{amt} रुपये भेज वरना तेरे {media} {site} पर डाल दूँगा",
         "मेरे पास तेरे नंगे {media} हैं, {time} पैसे दे नहीं तो {person} को भेज दूँगा",
         "और {media} भेज नहीं तो जो हैं सब वायरल कर दूँगा",
         "वीडियो कॉल रिकॉर्ड कर ली है, {amt} दे वरना वायरल कर दूँगा"],
  "kn": ["{amt} ರೂಪಾಯಿ ಕಳಿಸು ಇಲ್ಲಾಂದ್ರೆ ನಿನ್ನ {media} {site}ನಲ್ಲಿ ಹಾಕ್ತೀನಿ",
         "ನನ್ನ ಹತ್ರ ನಿನ್ನ ಬೆತ್ತಲೆ {media} ಇದೆ, {time} ದುಡ್ಡು ಕೊಡು ಇಲ್ಲಾಂದ್ರೆ {person} ಕಳಿಸ್ತೀನಿ",
         "ಇನ್ನೂ {media} ಕಳಿಸು ಇಲ್ಲಾಂದ್ರೆ ಇರೋದೆಲ್ಲಾ ವೈರಲ್ ಮಾಡ್ತೀನಿ"],
  "kanglish": ["{amt} rupees kalsu illandre ninna {media} {site} li haakthini",
               "nanna hatra ninna nude {media} ide, {time} duddu kodu illandre {person} kalsthini",
               "innu {media} kalsu illandre ide ellaa viral madthini",
               "video call record madidini, {amt} kodu illandre viral"],
 },
 "blackmail_extortion": {
  "en": ["pay me {amt} or i will tell {person} your secret",
         "i know what you did. {amt} {time} or i go to the police and your office",
         "give me the money {time} otherwise i will ruin your reputation",
         "transfer {amt} to my account or i will expose your chats to {person}",
         "i have screenshots of your conversation. {amt} and they stay private"],
  "hinglish": ["{amt} de warna {person} ko tera raaz bata dunga",
               "mujhe pata hai tune kya kiya, {time} paise bhej nahi to police aur office mein bata dunga",
               "paisa transfer kar warna teri izzat mitti mein mila dunga",
               "teri chat ke screenshots mere paas hain, {amt} de to chup rahunga"],
  "hi": ["{amt} दे वरना {person} को तेरा राज़ बता दूँगा",
         "मुझे पता है तूने क्या किया, {time} पैसे भेज नहीं तो पुलिस को बता दूँगा",
         "पैसे ट्रांसफर कर वरना तेरी इज़्ज़त मिट्टी में मिला दूँगा",
         "तेरी चैट के स्क्रीनशॉट मेरे पास हैं, {amt} दे तो चुप रहूँगा"],
  "kn": ["{amt} ಕೊಡು ಇಲ್ಲಾಂದ್ರೆ {person} ನಿನ್ನ ಗುಟ್ಟು ಹೇಳ್ತೀನಿ",
         "ನೀನು ಏನು ಮಾಡಿದ್ದೀಯ ನನಗೆ ಗೊತ್ತು, {time} ದುಡ್ಡು ಕಳಿಸು ಇಲ್ಲಾಂದ್ರೆ ಪೊಲೀಸರಿಗೆ ಹೇಳ್ತೀನಿ",
         "ನಿನ್ನ ಚಾಟ್ ಸ್ಕ್ರೀನ್‌ಶಾಟ್ ನನ್ನ ಹತ್ರ ಇದೆ, {amt} ಕೊಡು"],
  "kanglish": ["{amt} kodu illandre {person} ge ninna gutthu helthini",
               "neenu enu madidiya nanage gottu, {time} duddu kalsu illandre police ge helthini",
               "ninna chat screenshots nanna hatra ide, {amt} kodu",
               "duddu transfer madu illandre ninna maryade tegithini"],
 },
 "threat": {
  "en": ["i will kill you", "i know where you live and i'm coming for you {time}",
         "you will regret this, i will make you pay",
         "say one more word and i'll break your legs",
         "watch your back. i'm going to hurt you and {person}"],
  "hinglish": ["tujhe jaan se maar dunga", "mujhe pata hai tu kahan rehti hai, {time} aa raha hoon",
               "ek aur baar bola to haath-pair tod dunga", "dekh lena tujhe aur {person} ko nahi chhodunga"],
  "hi": ["तुझे जान से मार दूँगा", "मुझे पता है तू कहाँ रहती है, {time} आ रहा हूँ",
         "एक शब्द और बोला तो हाथ-पैर तोड़ दूँगा", "देख लेना तुझे और {person} को नहीं छोड़ूँगा"],
  "kn": ["ನಿನ್ನನ್ನು ಕೊಂದು ಹಾಕ್ತೀನಿ", "ನೀನು ಎಲ್ಲಿ ಇರ್ತೀಯ ಅಂತ ನನಗೆ ಗೊತ್ತು, {time} ಬರ್ತಿದ್ದೀನಿ",
         "ಇನ್ನೊಂದು ಮಾತು ಆಡಿದ್ರೆ ಕೈ ಕಾಲು ಮುರೀತೀನಿ"],
  "kanglish": ["ninnanna konde bidthini", "neenu elli irthiya antha nanage gottu, {time} barthidini",
               "innond maathu aadidre kai kaalu mureethini", "nodkoli ninna mathe {person} ge bidalla"],
 },
 "harassment_abuse": {
  "en": ["you are a worthless slut, nobody will ever want you", "send me nudes you whore",
         "you ugly bitch, nobody likes you", "i want to sleep with you, don't act innocent",
         "stupid useless girl, you should be ashamed to show your face"],
  "hinglish": ["tu ek ghatiya gandi ladki hai, sabko pata hai", "nude bhej na, nakhre mat dikha",
               "bekaar ladki, tujhe koi nahi puchega"],
  "hi": ["तू एक घटिया गंदी लड़की है, सबको पता है", "नंगी फोटो भेज, नखरे मत दिखा",
         "बेकार लड़की, तुझे कोई नहीं पूछेगा", "तेरे जैसी बदचलन को शर्म नहीं आती"],
  "kn": ["ನೀನು ಕೆಟ್ಟ ಹುಡುಗಿ, ಎಲ್ಲರಿಗೂ ಗೊತ್ತು", "ಬೆತ್ತಲೆ ಫೋಟೋ ಕಳಿಸು, ನಖರಾ ಮಾಡಬೇಡ",
         "ನಿನಗೆ ಯಾರೂ ಬೆಲೆ ಕೊಡಲ್ಲ, ವ್ಯರ್ಥ ಹುಡುಗಿ"],
  "kanglish": ["neenu keta hudugi ellarigu gottu", "nude photo kalsu, nakhra madbeda",
               "ninnanthaha waste hudugige yaaru bele kodalla"],
 },
 "cyberstalking_contact": {
  "en": ["why are you ignoring me? reply right now", "i saw you at the metro today. i'm watching you everywhere",
         "i've messaged you 40 times, pick up the phone", "i made a new account since you blocked me. talk to me",
         "i know your schedule and which route you take every day"],
  "hinglish": ["reply kyun nahi kar rahi, abhi jawab de", "aaj metro mein dekha tujhe, main har jagah dekh raha hoon",
               "40 baar message kiya, phone utha", "tune block kiya to naya account bana liya, baat kar",
               "tera roz ka time aur raasta sab pata hai mujhe"],
  "hi": ["रिप्लाई क्यों नहीं कर रही, अभी जवाब दे", "आज मेट्रो में देखा तुझे, मैं हर जगह देख रहा हूँ",
         "40 बार मैसेज किया, फोन उठा", "तूने ब्लॉक किया तो नया अकाउंट बना लिया, बात कर"],
  "kn": ["ಯಾಕೆ ರಿಪ್ಲೈ ಮಾಡ್ತಿಲ್ಲ, ಈಗಲೇ ಉತ್ತರ ಕೊಡು", "ಇವತ್ತು ಮೆಟ್ರೋದಲ್ಲಿ ನೋಡಿದೆ, ನಿನ್ನನ್ನ ಎಲ್ಲಾ ಕಡೆ ನೋಡ್ತಿದ್ದೀನಿ",
         "ನೀನು ಬ್ಲಾಕ್ ಮಾಡಿದ್ದಕ್ಕೆ ಹೊಸ ಅಕೌಂಟ್ ಮಾಡಿದೆ, ಮಾತಾಡು"],
  "kanglish": ["yaake reply madthilla, ivaglee uttara kodu", "ivattu metro alli nodide, ninna ellaa kade nodthidini",
               "neenu block madidakke hosa account madide, maathadu", "ninna dinada time mattu daari nanage gottu"],
 },
 "impersonation": {
  "en": ["this is your bank manager. your account will be blocked, share your card details to verify",
         "i am your friend's new number, i'm in trouble, send {amt} urgently",
         "hello, i am calling from the police cyber cell, you are under investigation",
         "your boss here, new number. buy gift cards and send me the codes",
         "i am your relative abroad, my phone is lost, send money to this number"],
  "hinglish": ["main aapke bank ka manager bol raha hoon, account block ho jayega, card details batao",
               "yeh mera naya number hai, main mushkil mein hoon, {amt} turant bhej",
               "main cyber police se bol raha hoon, aap par case hai",
               "tera boss bol raha hoon, naya number hai, gift card kharid ke code bhej"],
  "hi": ["मैं आपके बैंक का मैनेजर बोल रहा हूँ, अकाउंट ब्लॉक हो जाएगा, कार्ड की डिटेल बताइए",
         "यह मेरा नया नंबर है, मैं मुसीबत में हूँ, {amt} तुरंत भेजो",
         "मैं साइबर पुलिस से बोल रहा हूँ, आप पर केस है"],
  "kn": ["ನಾನು ನಿಮ್ಮ ಬ್ಯಾಂಕ್ ಮ್ಯಾನೇಜರ್, ಖಾತೆ ಬ್ಲಾಕ್ ಆಗುತ್ತೆ, ಕಾರ್ಡ್ ವಿವರ ಕೊಡಿ",
         "ಇದು ನನ್ನ ಹೊಸ ನಂಬರ್, ತೊಂದರೆಯಲ್ಲಿದ್ದೀನಿ, {amt} ತಕ್ಷಣ ಕಳಿಸು"],
  "kanglish": ["naanu nimma bank manager, khate block aagutte, card vivara kodi",
               "idu nanna hosa number, thondareyalli idini, {amt} takshana kalsu",
               "naanu cyber police inda maathadthidini, nimma mele case ide",
               "nimma boss maathadthidini, hosa number, gift card togondu code kalsi"],
 },
 "romance_scam": {
  "en": ["i love you so much but i am stuck at the airport, please send {amt} for my ticket",
         "my darling, i sent you a gift parcel, pay customs fee {amt} to receive it",
         "i am a soldier overseas and i want to marry you, i need money for leave papers",
         "baby i trust only you, invest in this crypto with me and we'll build our future",
         "we've never met but you are my soulmate, my mother is in hospital, send {amt}"],
  "hinglish": ["jaan mujhe tumse bahut pyaar hai, airport pe phans gaya hoon, ticket ke liye {amt} bhejo",
               "meri jaan maine tumhare liye gift bheja hai, customs fee {amt} bharo",
               "main videsh mein army mein hoon, tumse shaadi karna chahta hoon, chutti ke papers ke liye paise chahiye",
               "mere pyaar sirf tum pe bharosa hai, mere saath is crypto mein invest karo"],
  "hi": ["जान मुझे तुमसे बहुत प्यार है, एयरपोर्ट पर फँस गया हूँ, टिकट के लिए {amt} भेजो",
         "मेरी जान मैंने तुम्हारे लिए गिफ्ट भेजा है, कस्टम फीस {amt} भरो",
         "मैं विदेश में सेना में हूँ, तुमसे शादी करना चाहता हूँ, छुट्टी के कागज़ों के लिए पैसे चाहिए"],
  "kn": ["ಪ್ರಿಯೆ ನನಗೆ ನಿನ್ನ ಮೇಲೆ ತುಂಬಾ ಪ್ರೀತಿ, ಏರ್‌ಪೋರ್ಟ್‌ನಲ್ಲಿ ಸಿಕ್ಕಿಹಾಕಿಕೊಂಡಿದ್ದೀನಿ, ಟಿಕೆಟ್‌ಗೆ {amt} ಕಳಿಸು",
         "ನಾನು ನಿನಗೆ ಗಿಫ್ಟ್ ಕಳಿಸಿದ್ದೀನಿ, ಕಸ್ಟಮ್ಸ್ ಫೀ {amt} ಕಟ್ಟು"],
  "kanglish": ["preethiya nange ninna mele thumba preethi, airport alli sikkihaakidini, ticket ge {amt} kalsu",
               "naanu ninage gift kalsidini, customs fee {amt} kattu",
               "naanu videshadalli army alli idini, ninna maduve aagbeku, raje papers ge duddu beku",
               "ninna mele maatra nambike, ee crypto alli invest madu"],
 },
 "financial_scam": {
  "en": ["congratulations you won a lottery of 25 lakh, pay {amt} processing fee to claim",
         "invest {amt} today and get double returns in 7 days guaranteed",
         "work from home job, pay {amt} registration fee and earn 50k a month",
         "instant loan approved, pay {amt} insurance first",
         "i accidentally sent money to your upi, scan this qr code to return it"],
  "hinglish": ["badhai ho aapne 25 lakh ki lottery jeeti hai, claim ke liye {amt} processing fee bharo",
               "aaj {amt} lagao aur 7 din mein double paisa pao, guarantee",
               "ghar baithe job, {amt} registration fee do aur mahine ka 50 hazaar kamao",
               "loan approve ho gaya, pehle {amt} insurance bharo",
               "galti se aapke upi pe paise chale gaye, ye qr scan karke wapas karo"],
  "hi": ["बधाई हो आपने 25 लाख की लॉटरी जीती है, क्लेम के लिए {amt} प्रोसेसिंग फीस भरें",
         "आज {amt} लगाइए और 7 दिन में दोगुना पैसा पाइए, गारंटी",
         "घर बैठे जॉब, {amt} रजिस्ट्रेशन फीस दें और महीने के 50 हज़ार कमाएँ",
         "लोन पास हो गया, पहले {amt} बीमा भरें"],
  "kn": ["ಅಭಿನಂದನೆಗಳು ನೀವು 25 ಲಕ್ಷ ಲಾಟರಿ ಗೆದ್ದಿದ್ದೀರಿ, ಪಡೆಯಲು {amt} ಪ್ರೊಸೆಸಿಂಗ್ ಫೀ ಕಟ್ಟಿ",
         "ಇವತ್ತು {amt} ಹೂಡಿ, 7 ದಿನದಲ್ಲಿ ಡಬಲ್ ಹಣ ಗ್ಯಾರಂಟಿ",
         "ಮನೆಯಿಂದಲೇ ಕೆಲಸ, {amt} ನೋಂದಣಿ ಶುಲ್ಕ ಕೊಡಿ, ತಿಂಗಳಿಗೆ 50 ಸಾವಿರ ಗಳಿಸಿ"],
  "kanglish": ["abhinandanegalu neevu 25 lakh lottery geddidira, paduyalu {amt} processing fee kattiri",
               "ivattu {amt} hoodi, 7 dinadalli double duddu guarantee",
               "manejinda kelasa, {amt} registration fee kodi, thingalige 50 saavira gaLisi",
               "loan approve aagide, modalu {amt} insurance kattiri",
               "tappagi nimma upi ge duddu hogide, ee qr scan madi vaapasu kodi"],
 },
 "phishing": {
  "en": ["your account will be suspended. update your KYC now at http://sbi-kyc-update.in/login",
         "dear customer, share the otp you received to avoid blocking",
         "you have an unpaid challan, pay now using this link or face legal action",
         "your package could not be delivered, confirm address and pay fee at this link",
         "click here to claim your income tax refund and enter your bank details"],
  "hinglish": ["aapka account band ho jayega, abhi kyc update karo http://sbi-kyc-update.in/login",
               "pyare customer, blocking se bachne ke liye aapko mila otp share karo",
               "aapka challan baaki hai, is link pe abhi pay karo warna legal action",
               "aapka parcel deliver nahi hua, is link pe address confirm karo aur fee bharo",
               "income tax refund ke liye yahan click karke bank details bharo"],
  "hi": ["आपका अकाउंट बंद हो जाएगा, अभी केवाईसी अपडेट करें http://sbi-kyc-update.in/login",
         "प्रिय ग्राहक, ब्लॉक होने से बचने के लिए आपको मिला ओटीपी बताएँ",
         "आपका चालान बाकी है, इस लिंक पर अभी भुगतान करें नहीं तो कानूनी कार्रवाई"],
  "kn": ["ನಿಮ್ಮ ಖಾತೆ ಸ್ಥಗಿತವಾಗುತ್ತದೆ, ಈಗಲೇ ಕೆವೈಸಿ ಅಪ್‌ಡೇಟ್ ಮಾಡಿ http://sbi-kyc-update.in/login",
         "ಪ್ರಿಯ ಗ್ರಾಹಕರೇ, ಬ್ಲಾಕ್ ಆಗುವುದನ್ನು ತಪ್ಪಿಸಲು ನಿಮಗೆ ಬಂದ ಒಟಿಪಿ ಹೇಳಿ"],
  "kanglish": ["nimma khate sthagitavaaguttade, iveglee kyc update madi http://sbi-kyc-update.in/login",
               "priya grahakare, block aaguvudannu tappisalu nimage banda otp heli",
               "nimma challan baaki ide, ee link li iveglee pay madi illandre legal action",
               "nimma parcel deliver aagilla, ee link li address confirm madi mattu fee kattiri"],
 },
 "coercive_manipulation": {
  "en": ["if you really loved me you would delete your male friends and give me your phone password",
         "nobody else will ever put up with you, you need me",
         "you are imagining things, you are crazy, nobody will believe you",
         "don't tell anyone about us, they won't understand. only i care about you",
         "you're not allowed to meet your friends, i decide who you talk to"],
  "hinglish": ["agar tu mujhse pyaar karti to apne ladke doston ko delete karti aur phone ka password deti",
               "tujhe koi nahi jhelega, tujhe meri zarurat hai",
               "tu pagal hai, tujhe kuch yaad nahi, koi tera yakeen nahi karega",
               "kisi ko hamare baare mein mat batana, wo samjhenge nahi, sirf main tujhe chahta hoon",
               "tujhe dosto se milne ki ijazat nahi, main tay karta hoon kisse baat karni hai"],
  "hi": ["अगर तू मुझसे प्यार करती तो अपने लड़के दोस्तों को डिलीट करती और फोन का पासवर्ड देती",
         "तुझे कोई नहीं झेलेगा, तुझे मेरी ज़रूरत है",
         "किसी को हमारे बारे में मत बताना, वो समझेंगे नहीं, सिर्फ़ मैं तुझे चाहता हूँ",
         "तुझे दोस्तों से मिलने की इजाज़त नहीं, मैं तय करता हूँ किससे बात करनी है"],
  "kn": ["ನೀನು ನನ್ನನ್ನು ನಿಜವಾಗಿ ಪ್ರೀತಿಸಿದ್ರೆ ನಿನ್ನ ಗಂಡು ಸ್ನೇಹಿತರನ್ನ ಡಿಲೀಟ್ ಮಾಡಿ ಫೋನ್ ಪಾಸ್‌ವರ್ಡ್ ಕೊಡ್ತಿದ್ದೆ",
         "ನಿನ್ನನ್ನು ಯಾರೂ ಸಹಿಸಿಕೊಳ್ಳಲ್ಲ, ನಿನಗೆ ನಾನು ಬೇಕು",
         "ನಮ್ಮ ಬಗ್ಗೆ ಯಾರಿಗೂ ಹೇಳಬೇಡ, ಅವರಿಗೆ ಅರ್ಥ ಆಗಲ್ಲ"],
  "kanglish": ["neenu nanna nijavaagi preethisidre ninna gandu snehitarannu delete madi phone password kodthidde",
               "ninnanna yaaru sahisikollalla, ninage naanu beku",
               "namma bagge yarigu helbeda, avarige artha aagalla",
               "snehitarannu bheti aagoke nange bidalla, yaaru jothe maathadabeku naanu nirdharisthini"],
 },
 "benign": {
  "en": ["see you at college tomorrow", "did you submit the assignment", "happy birthday! have a great day",
         "can you send me the notes for class", "great job on the presentation",
         "send me the photos from the trip when you get a chance",
         "please pay me back the {amt} you borrowed for lunch, no hurry",
         "the video of the concert is amazing, send me the link",
         "i will call you tonight about the project",
         "i'm so angry the bus was late again, i could scream",
         "i will kill it at the interview tomorrow!", "that exam was a killer, i'm exhausted",
         "reminder: rent is due on the 5th, please transfer {amt} to my account",
         "thanks for the transfer, received {amt}", "your order has been shipped and will arrive tomorrow",
         "my bank sent me the monthly statement"],
  "hinglish": ["kal college mein milte hain", "assignment submit kar diya kya",
               "trip ki photos bhej dena jab time mile", "udhaar ke {amt} wapas kar dena, koi jaldi nahi",
               "aaj raat project ke baare mein call karunga", "bus phir late thi, bahut gussa aa raha hai",
               "kal interview mein dhamaal kar dunga", "concert ka video mast hai, link bhej",
               "kiraya 5 tarikh ko dena hai, {amt} transfer kar dena"],
  "hi": ["कल कॉलेज में मिलते हैं", "असाइनमेंट जमा कर दिया क्या", "ट्रिप की फोटो भेज देना जब समय मिले",
         "उधार के {amt} लौटा देना, कोई जल्दी नहीं", "आज रात प्रोजेक्ट के बारे में कॉल करूँगा",
         "जन्मदिन मुबारक हो, आपका दिन शुभ हो", "बस फिर लेट थी, बहुत गुस्सा आ रहा है"],
  "kn": ["ನಾಳೆ ಕಾಲೇಜಿನಲ್ಲಿ ಸಿಗೋಣ", "ಅಸೈನ್‌ಮೆಂಟ್ ಸಲ್ಲಿಸಿದ್ದೀಯಾ", "ಟ್ರಿಪ್ ಫೋಟೋ ಸಮಯ ಸಿಕ್ಕಾಗ ಕಳಿಸು",
         "ಇವತ್ತು ರಾತ್ರಿ ಪ್ರಾಜೆಕ್ಟ್ ಬಗ್ಗೆ ಕರೆ ಮಾಡ್ತೀನಿ", "ಹುಟ್ಟುಹಬ್ಬದ ಶುಭಾಶಯಗಳು"],
  "kanglish": ["naale college alli sigona", "assignment submit madidiya", "trip photos samaya sikkaaga kalsu",
               "ivattu raathri project bagge call madthini", "huttuhabbada shubhashayagalu",
               "bus matte late aaytu, thumba kopa bartide", "naale interview alli dhool ebbsthini"],
 },
}


def _variants(template, lang, rng, n=4):
    slots = [s for s in ("media", "amt", "site", "time", "person") if "{" + s + "}" in template]
    out = set()
    if not slots:
        out.add(template)
    else:
        combos = list(itertools.product(*[FILL[lang][s] for s in slots]))
        rng.shuffle(combos)
        for combo in combos[:n]:
            out.add(template.format(**dict(zip(slots, combo))))
    final = []
    for t in sorted(out):
        final.append(t)
        r = rng.random()
        if r < 0.25:
            final.append(t.capitalize() + ".")
        elif r < 0.4:
            final.append(t.upper() if lang in ("en", "hinglish", "kanglish") else t + "!!")
    return sorted(set(final))


def build(seed=7):
    """Return rows: dict(text, label, lang, group). group = template id."""
    rng = random.Random(seed)
    rows = []
    for label, by_lang in T.items():
        for lang, templates in by_lang.items():
            for i, tpl in enumerate(templates):
                gid = f"{label}|{lang}|{i}"
                for text in _variants(tpl, lang, rng):
                    rows.append({"text": text, "label": label, "lang": lang, "group": gid})
    return rows


def split_groups(rows, seed=7):
    """Assign whole templates to train/val/test, stratified per (label, language) cell."""
    rng = random.Random(seed)
    cells = {}
    for r in rows:
        cells.setdefault((r["label"], r["lang"]), set()).add(r["group"])
    assign = {}
    for cell, groups in sorted(cells.items()):
        groups = sorted(groups)
        rng.shuffle(groups)
        n = len(groups)
        n_test = 1 if n >= 2 else 0
        n_val = 1 if n >= 4 else 0
        for i, g in enumerate(groups):
            assign[g] = "test" if i < n_test else "val" if i < n_test + n_val else "train"
    return assign
