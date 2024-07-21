#PROJECT SOTERIA
import tkinter as tk
import customtkinter as ctk
import os
import pyttsx3
import threading
import speech_recognition as sr
import yara
import glob
import time 
import stat
import datetime
import pefile
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# TEXT TO SPEECH SET UP
engine = pyttsx3.init()

# GLOBALS

QUARANTINE_FOLDER = r"C:\Users\ACER\Desktop\Soteria\YARA\QUARANTINE"
malicious_files_report = []

def text_to_speech(text, from_voice=False):
    print("Check SPEECH")
    if (tts_enabled.get() and not from_voice) or (voice_tts_enabled.get() and from_voice):
        engine.say(text)
        engine.runAndWait()

#MAIN SOTERIA RESPONSES
def chatbot_response(user_input):
    print("Check RESPONSE")
    response = ""
    user_input = user_input.lower()

    if "create folder" in user_input or "create a folder" in user_input:
        if "named" in user_input and "at" in user_input:
            folder_name_part = user_input.split("named")[-1].split("at")[0].strip()
            location_part = get_location(user_input)
            response = create_folder(folder_name_part, location_part)
        else:
            folder_name = user_input.split("named")[-1].strip() if "named" in user_input else ""
            location = get_location(user_input)
            response = create_folder(folder_name, location)
            
    elif "create file" in user_input or "create a file" in user_input:
        file_details = user_input.split("named")[-1].strip() if "named" in user_input else ""
        response = create_file(file_details)

    elif "find file" in user_input or "find folder" in user_input:
        file_name = user_input.split("find")[-1].strip() if "find" in user_input else ""
        response = search_file(file_name)

    elif "execute file" in user_input:
        file_name = user_input.split("execute file")[-1].strip() if "execute file" in user_input else ""
        response = execute_file(file_name)

    elif "scan for malicious files" in user_input or "are there malicious files" in user_input:
        response = check_malicious_files()
        
    elif "can you scan my pc for any malicious files or anything sketchy" in user_input or "scan my pc" in user_input:
        response = check_malicious_files()

    elif "isolate them further" in user_input:
        response = isolate_threats()

    elif "show me the report" in user_input or "view the report" in user_input:
        response = open_report_window()

    elif "save this report" in user_input:
        response = save_report()
        
    elif "show me the malicious files" in user_input:
        show_malicious_files()
        
    elif "delete" in user_input:
        delete_malicious_files(user_input)

    else:
        response = basic_commands(user_input)

    return response
#SUB FEATURES OF SOTERIA ==========================================================================================================================================
#SEARCH FILE IN THE PC 
def search_file(file_name):
    print("Check SEARCH")
    try:
        search_pattern = f"**/{file_name}*"
        found_files = glob.glob(search_pattern, recursive=True)
        if found_files:
            response = f"Found {len(found_files)} file(s):\n" + "\n".join(found_files)
        else:
            response = "No files found."
        return response
    except Exception as e:
        return f"Error searching file: {e}"

#TO GET THE LOCATION
def get_location(command):
    print("Check LOCATE")
    try:
        if "at" in command:
            return command.split("at")[-1].strip()
        else:
            return os.getcwd()
    except Exception as e:
        return f"Error getting location: {e}"

#CREATING A FOLDER
def create_folder(folder_name, location):
    print("Check CREATE")
    try:
        if not folder_name:
            return "Please provide a name for the folder."
        
        path = os.path.join(location, folder_name)
        os.makedirs(path, exist_ok=True)
        return f"Folder '{folder_name}' created successfully at {path}."
    except Exception as e:
        return f"Error creating folder: {e}"

#CREATING A FILE
def create_file(file_details):
    try:
        if not file_details:
            return "Please provide details for the file."

        parts = file_details.split()
        file_name = parts[0]
        location = get_location(file_details)

        path = os.path.join(location, file_name) 
        with open(path, 'w') as file:
            file.write("")  # Create an empty file
        return f"File '{file_name}' created successfully at {path}."
    except Exception as e:
        return f"Error creating file: {e}"
#SEARCHING FILE
def search_file(file_name):
    print("Check SEARCH")
    try:
        if not file_name:
            return "Please provide the name of the file or folder to search for."

        for root, dirs, files in os.walk("C:\\"):  # Modify the path as needed
            if file_name in files or file_name in dirs:
                return f"Found: {os.path.join(root, file_name)}"
        return "File or folder not found"
    except Exception as e:
        return f"Error searching file: {e}"
#OPENING THE FILE
def execute_file(file_name):
    try:
        file_path = search_file(file_name)
        if "Found:" in file_path:
            os.startfile(file_path.split("Found:")[-1].strip())
            return f"File '{file_name}' executed successfully."
        return file_path
    except Exception as e:
        return f"Error executing file: {e}"
    
# MAIN FEATURES OF SOTERIA =======================================================================================================
#UNDERSTANDING LOGIC INTERPRET MALICIOUS FILE 
def get_file_metadata(file_path):
    print("Check METADATA")
    try:
        file_stats = os.stat(file_path)
        creation_time = datetime.datetime.fromtimestamp(file_stats.st_ctime)
        
        last_access_time = datetime.datetime.fromtimestamp(file_stats.st_atime)
        
        last_modification_time = datetime.datetime.fromtimestamp(file_stats.st_mtime)
        
        file_permissions = stat.filemode(file_stats.st_mode)
        
        try:
            pe = pefile.PE(file_path)
            developer_info = pe.FileInfo[0][0].StringTable[0].entries.get(b'CompanyName', b'Unknown').decode('utf-8')
        except Exception as e:
            developer_info = "Unknown"

        return {
            "creation_time": creation_time,
            "last_access_time": last_access_time,
            "last_modification_time": last_modification_time,
            "file_permissions": file_permissions,
            "developer_info": developer_info
        }
    except Exception as e:
        print(f"Error retrieving file metadata: {e}")
        return None
#IF SUS
def is_file_suspicious(metadata):
    print("Check SUS")
    
    suspicious_developers = ["Unknown"]
    suspicious_permissions = ["-rw-rw-rw-", "rwxrwxrwx"]
    suspicious_time_threshold = datetime.datetime.now() - datetime.timedelta(days=1)  # Recent file
    
    if metadata["developer_info"] in suspicious_developers:
        return True
    if metadata["file_permissions"] in suspicious_permissions:
        return True
    if metadata["creation_time"] > suspicious_time_threshold:
        return True
    if metadata["last_access_time"] > suspicious_time_threshold:
        return True
    if metadata["last_modification_time"] > suspicious_time_threshold:
        return True
    
    return False
#SCANNING SECTION
def check_malicious_files():
    print("Check MALICIOUS")    
    try:
        global malicious_files_report
        malicious_files_report.clear()
        yara_path = r'C:\Users\ACER\Desktop\Soteria\YARA\malware_index.yar' #CHANGE THIS AS NEEDED / EXAMPLE OF PATH DIRECTORY
        rules = None

        print("Loading YARA rules...")
        try:
            rules = yara.compile(filepath=yara_path)
        except Exception as e:
            print(f"Error loading YARA rule: {e}")

        if rules:
            print("YARA rules loaded successfully.")
            for root, dirs, files in os.walk("C:\\"):  # Modify the path as needed
                for file in files:
                    file_path = os.path.join(root, file)
                    metadata = get_file_metadata(file_path)
                    if metadata and is_file_suspicious(metadata):
                        malicious_files_report.append(file_path)
                    try:
                        matches = rules.match(filepath=file_path)
                        if matches:
                            malicious_files_report.append(file_path)
                    except Exception as e:
                        print(f"Error scanning file with YARA: {e}")

        if malicious_files_report:
            response = "Initiating virus scan now...\n\n"
            response += "Scan complete. I found potential threats:\n"
            for file_path in malicious_files_report:
                response += f"{file_path}\n"
            response += "\nThese files have been isolated. What would you like to do with them?"
        else:
            response = "Initiating virus scan now...\n\n"
            response += "Scan complete. No malicious files detected."

        app.after(0, open_report_window, response)
        
    except Exception as e:
        return f"Error checking malicious files: {e}"
    
def update_report_area():
    global report_area
    report_area.configure(state='normal')
    report_area.delete(1.0, tk.END)
    for line in malicious_files_report:
        report_area.insert(tk.END, line + '\n')
    report_area.configure(state='disabled')

#REPORTS WINDOW SECTION
def open_report_window(response):
    print("Check REPORT")    
    try:
        report_window = ctk.CTkToplevel(app)
        report_window.title("Scan Reports Soteria")
        report_window.geometry("600x500")

        report_text = ctk.CTkTextbox(report_window, width=560, height=300, state='normal', wrap='word', border_width=1, corner_radius=12)
        report_text.grid(row=0, column=0, columnspan=2, padx=20, pady=10, sticky='nsew')

        isolate_button = ctk.CTkButton(report_window, text="Isolate", command=isolate_threats, corner_radius=12, hover_color="#ADD8E6")
        isolate_button.grid(row=1, column=0, padx=10, pady=10, sticky='ew')

        save_button = ctk.CTkButton(report_window, text="Save Report", command=save_report, corner_radius=12, hover_color="#ADD8E6")
        save_button.grid(row=1, column=1, padx=10, pady=10, sticky='ew')

        report_window.grid_rowconfigure(0, weight=1)
        report_window.grid_rowconfigure(1, weight=0)
        report_window.grid_columnconfigure(0, weight=1)
        report_window.grid_columnconfigure(1, weight=1)

        report_text.insert("1.0", response)
        report_text.configure(state='disabled')
    except Exception as e:
        print(f"Error opening report window: {e}")

#QUARANTINE
def isolate_threats():
    print("Check ISOLATE")    
    try:
        global malicious_files_report
        if malicious_files_report:
            quarantine_path = r"C:\Users\ACER\Desktop\Soteria\YARA\QUARANTINE"
            for file_path in malicious_files_report:
                os.makedirs(quarantine_path, exist_ok=True)
                file_name = os.path.basename(file_path)
                new_path = os.path.join(quarantine_path, file_name)
                os.rename(file_path, new_path)

            malicious_files_report = [] 
            return "Done. Threats have been moved to quarantine."
        else:
            return "No threats to isolate."
    except Exception as e:
        return f"Error isolating threats: {e}"
#SAVING REPORT
def save_report():
    print("Check SAVE")    
    try:
        report_file = "malicious_files_report.txt"
        with open(report_file, 'w') as file:
            if malicious_files_report:
                file.write("Detected threats:\n")
                for file_path in malicious_files_report:
                    file.write(f"- {file_path}\n")
            else:
                file.write("No threats detected.\n")

        return "Report saved successfully."
    except Exception as e:
        return f"Error saving report: {e}"
    
#OPENING THE FOLDER OF QUARANTINE
def show_malicious_files():
    if os.path.exists(QUARANTINE_FOLDER):
        files = os.listdir(QUARANTINE_FOLDER)
        if files:
            print("Quarantined Malicious Files:")
            for file in files:
                print(file)
        else:
            print("No malicious files found in the quarantine folder.")
    else:
        print("Quarantine folder does not exist.")
        
#DELETING FILES
def delete_malicious_files(user_input):
    try:
        _, file_name = user_input.split(' ', 1)
        file_path = os.path.join(QUARANTINE_FOLDER, file_name)
        if os.path.exists(file_path):
            os.remove(file_path)
            print(f"Deleted file: {file_name}")
        else:
            print(f"File not found: {file_name}")
    except Exception as e:
        print(f"Error deleting file: {e}")

#REAL TIME PROTECTION SECTION JAMES DO NOT TOUCH UNLES NECESSARY ====================================================================================================
class RealTimeScanHandler(FileSystemEventHandler):
    def __init__(self, yara_rules):
        self.rules = yara_rules

    def on_modified(self, event):
        if not event.is_directory:
            file_path = event.src_path
            metadata = get_file_metadata(file_path)
            if metadata and is_file_suspicious(metadata):
                print(f"Suspicious file detected: {file_path}")
                print(f"Metadata: {metadata}")
                malicious_files_report.append(file_path)
            try:
                matches = self.rules.match(filepath=file_path)
                if matches:
                    malicious_files_report.append(file_path)
                update_report_area()
            except Exception as e:
                print(f"Error scanning file with YARA: {e}")

# Real-time scan functions
real_time_observer = None

def start_real_time_scan_thread():
    global real_time_observer
    yara_path = r'C:\Users\ACER\Desktop\Soteria\YARA\malware_index.yar' #CHANGE THIS AS NEEDED / EXAMPLE OF PATH DIRECTORY
    print("Loading YARA rules...")
    try:
        rules = yara.compile(filepath=yara_path)
        print("YARA rules loaded successfully.")
        real_time_observer = threading.Thread(target=start_real_time_scan, args=("C:\\", rules))
        real_time_observer.daemon = True
        real_time_observer.start()
    except Exception as e:
        print(f"Error loading YARA rule: {e}")

def stop_real_time_scan_thread():
    global real_time_observer
    if real_time_observer:
        real_time_protection_enabled.set(False)
        real_time_observer.join()
        real_time_observer = None

def start_real_time_scan(path_to_watch, yara_rules):
    event_handler = RealTimeScanHandler(yara_rules)
    observer = Observer()
    observer.schedule(event_handler, path=path_to_watch, recursive=True)
    observer.start()
    try:
        while real_time_protection_enabled.get():
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.stop()
    observer.join()

def toggle_real_time_protection():
    if real_time_protection_enabled.get():
        start_real_time_scan_thread()
    else:
        stop_real_time_scan_thread()

#START SCAN
def start_scan():
    threading.Thread(target=check_malicious_files).start()
    

#STANDARD CONVERSATION PROMPTS ===========================================================================================================================
def basic_commands(user_input):
    responses = {
        "hello": "Hey there! Soteria here, your friendly AI assistant and Guardian. What can I help you with today?",
        "hi": "Hi there! Ready to conquer your PC tasks? Just let me know what you need.",
        "how are you": "I'm doing great, thanks for asking! Always on standby to assist you with your PC needs.",
        "who are you": "I'm Soteria, your AI assistant here to make your PC experience a breeze! Need help opening apps, finding files, or staying safe online? I'm your one-stop shop!",
        "what can you do": "I'm your ultimate PC guardian. I can assist you in using your personal computer and mainly protect your PC against malicious files, malware, and even viruses.",
        "can you understand me": "Absolutely! I can understand both text and voice commands. Speak your mind, and I'll be here to listen.",
        "can you tell me ": "Sure, what would you like to know? I can access information online or use my knowledge to help you with your PC tasks.", 
        "goodbye": "See you later! Have a productive day, and remember, Soteria is always here to help when you need me!",
        "thanks": "You're welcome! That's what I'm here for. Is there anything else I can assist you with today?",
        "thank you": "You're welcome! I'm here to help. Anything else you need assistance with?",
        "cybersecurity tips": (
            "Sure! Here are some cybersecurity tips:\n"
            "1. Use strong, unique passwords for different accounts.\n"
            "2. Enable two-factor authentication whenever possible.\n"
            "3. Keep your software and operating system up to date.\n"
            "4. Be cautious of suspicious emails and links.\n"
            "5. Regularly back up your data.\n"
            "6. Use antivirus software and keep it updated.\n"
            "7. Secure your Wi-Fi network with a strong password.\n"
            "8. Be careful when downloading software and apps.\n"
            "9. Monitor your accounts for any suspicious activity.\n"
            "10. Educate yourself about the latest cybersecurity threats.\n"
            "Need more tips or have specific questions?"
        ),
        "security concerns": (
            "I can help with that! What specific security concerns do you have?\n"
            "1. Phishing: Be cautious of emails or messages asking for personal information.\n"
            "2. Malware: Avoid downloading files from untrusted sources.\n"
            "3. Ransomware: Regularly back up your data to avoid losing access.\n"
            "4. Data breaches: Use strong, unique passwords for each account.\n"
            "5. Identity theft: Monitor your accounts for any unusual activity.\n"
            "6. Public Wi-Fi: Avoid accessing sensitive information on public networks.\n"
            "Feel free to ask more specific questions or concerns you might have!"
        ),
        "phishing": "Phishing is a method used by cybercriminals to trick you into revealing personal information. Be cautious of emails or messages that ask for sensitive information, especially if they come from unknown sources.",
        "malware": "Malware is malicious software designed to harm or exploit any programmable device or network. Always use antivirus software and keep it updated, and avoid downloading files from untrusted sources.",
        "ransomware": "Ransomware is a type of malware that encrypts your data and demands payment for the decryption key. Regularly back up your data to a separate location to avoid losing access.",
        "data breach": "A data breach is an incident where sensitive, protected, or confidential data is accessed or disclosed without authorization. Use strong, unique passwords for each account and monitor your accounts for any unusual activity.",
        "identity theft": "Identity theft occurs when someone uses your personal information without your permission to commit fraud or other crimes. Monitor your accounts regularly for any suspicious activity and use strong, unique passwords.",
        "public wi-fi": "Public Wi-Fi networks can be insecure, making it easier for attackers to intercept your data. Avoid accessing sensitive information when connected to public Wi-Fi, and use a VPN if necessary.",
        "strong passwords": "Creating strong passwords is crucial for protecting your online accounts. Use a mix of letters, numbers, and special characters, and avoid using easily guessable information like your name or birthdate.",
        "two-factor authentication": "Two-factor authentication (2FA) adds an extra layer of security by requiring not just a password and username but also something that only the user has on them, like a piece of information only they should know or have immediately to hand.",
        "antivirus": "Using antivirus software helps protect your computer from viruses, malware, and other security threats. Make sure your antivirus software is always up to date for maximum protection.",
        "software updates": "Keeping your software and operating system up to date is essential for security. Updates often include patches for security vulnerabilities that have been discovered.",
        "backing up data": "Regularly backing up your data ensures that you can recover your information in case of data loss due to hardware failure, malware, or other issues. Use external drives or cloud storage for backups.",
        "vpn": "A Virtual Private Network (VPN) encrypts your internet connection, providing additional security and privacy when using public Wi-Fi or other untrusted networks.",
        "suspicious emails": "Be cautious of emails from unknown senders, especially those asking for personal information or containing links and attachments. Verify the sender's identity before responding or clicking on any links.",
        "safe browsing": "Practicing safe browsing habits can protect you from many online threats. Avoid visiting suspicious websites, and be mindful of the links you click on and the files you download.",
        "firewall": "A firewall is a network security device that monitors and controls incoming and outgoing network traffic based on predetermined security rules. Make sure your firewall is enabled to protect your network."
    }
    for key, value in responses.items():
        if key in user_input:
            return value
    return "I'm sorry, I didn't quite understand that. Could you please rephrase your question or command?"


#TEXT AND VOICE HANDELING 
def process_text_input(event=None):
    user_input = user_input_entry.get()
    if user_input.strip():
        chat_log_text.configure(state='normal')
        chat_log_text.insert(tk.END, f"You: {user_input}\n")
        response = chatbot_response(user_input)
        chat_log_text.insert(tk.END, f"Soteria: {response}\n\n")
        chat_log_text.configure(state='disabled')
        user_input_entry.delete(0, tk.END)
        text_to_speech(response)

#VOICE COMMAND
def process_voice_input(): 
    recognizer = sr.Recognizer()
    with sr.Microphone() as source:
        print("Listening...")
        audio = recognizer.listen(source)
    try:
        voice_input = recognizer.recognize_google(audio)
        chat_log_text.configure(state='normal')
        chat_log_text.insert(tk.END, f"You (voice): {voice_input}\n")
        response = chatbot_response(voice_input)
        chat_log_text.insert(tk.END, f"Soteria: {response}\n\n")
        chat_log_text.configure(state='disabled')
        text_to_speech(response, from_voice=True)
    except sr.UnknownValueError:
        chat_log_text.configure(state='normal')
        chat_log_text.insert(tk.END, "Soteria: Sorry, I didn't catch that.\n\n")
        chat_log_text.configure(state='disabled')

#DESIGN AND APPEARANCE OF SOTERIA ==============================================================================================================================
ctk.set_appearance_mode("dark")  
ctk.set_default_color_theme("blue")  

#WINDOWS
app = ctk.CTk()
app.title("Soteria AI Assistant")
app.geometry("700x500")

# UI Elements 
chat_log_text = ctk.CTkTextbox(app, width=560, height=300, state="disabled", wrap='word', border_width=1, corner_radius=12)
chat_log_text.grid(row=0, column=0, columnspan=3, padx=20, pady=10, sticky='nsew')

user_input_entry = ctk.CTkEntry(app, width=400, corner_radius=12)
user_input_entry.grid(row=1, column=0, padx=10, pady=10, sticky='ew')

#BUTTONS
text_input_button = ctk.CTkButton(app, text="Send", command=process_text_input, corner_radius=12, hover_color="#ADD8E6")
text_input_button.grid(row=1, column=1, padx=10, pady=10, sticky='ew')

voice_input_button = ctk.CTkButton(app, text="Voice Command", command=process_voice_input, corner_radius=12, hover_color="#ADD8E6")
voice_input_button.grid(row=1, column=2, padx=10, pady=10, sticky='ew')

scan_button = ctk.CTkButton(app, text="Scan for Malicious Files", command=start_scan, corner_radius=12, hover_color="#ADD8E6")
scan_button.grid(row=2, column=0, columnspan=3, padx=10, pady=10, sticky='ew')

#SWITCHES
tts_enabled = tk.BooleanVar()
tts_switch = ctk.CTkSwitch(app, text="Enable TTS", variable=tts_enabled, corner_radius=12)
tts_switch.grid(row=3, column=0, padx=10, pady=10, sticky='ew')

real_time_protection_enabled = tk.BooleanVar()
real_time_protection_switch = ctk.CTkSwitch(app, text="Enable Real-Time Protection", variable=real_time_protection_enabled, command=toggle_real_time_protection, corner_radius=12)
real_time_protection_switch.grid(row=3, column=2, padx=10, pady=10, sticky='ew')

voice_tts_enabled = tk.BooleanVar()
voice_tts_switch = ctk.CTkSwitch(app, text="Enable Voice TTS", variable=voice_tts_enabled, corner_radius=12)
voice_tts_switch.grid(row=3, column=1, padx=10, pady=10, sticky='ew')

# MAKES THE UI RESPONSIVE ==========================================================================================================
app.grid_rowconfigure(0, weight=1)
app.grid_rowconfigure(1, weight=0)
app.grid_rowconfigure(2, weight=0)
app.grid_rowconfigure(3, weight=0)
app.grid_columnconfigure(0, weight=1)
app.grid_columnconfigure(1, weight=0)
app.grid_columnconfigure(2, weight=1)

user_input_entry.bind("<Return>", process_text_input)

# DO NOT DELETE JAMES
app.mainloop()