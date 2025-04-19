import telebot
from telebot import types
import os
import time
import threading
import requests
from requests import post, get
from rich.console import Console
import concurrent.futures
import json
import random
import sys
import re

BOT_TOKEN = "7470727246:AAHuF24HcdWfomigqsbJ9Z3BlLfMEukzB-Y"
bot = telebot.TeleBot(BOT_TOKEN)
console = Console()

user_states = {}
user_data = {}
session_cache = {}
active_reports = {}

class UserState:
    IDLE = 'idle'
    AWAITING_TARGET_ID = 'awaiting_target_id'
    AWAITING_REPORT_TYPE = 'awaiting_report_type'
    AWAITING_REPORTS_PER_SESSION = 'awaiting_reports_per_session'
    AWAITING_SLEEP_TIME = 'awaiting_sleep_time'
    REPORTING = 'reporting'
    AWAITING_SESSIONS_INPUT = 'awaiting_sessions_input'

report_options = {
    1: ("Spam", "Report spam content or behavior"),
    2: ("Self", "Report self-harm content"),
    3: ("Drugs", "Report drug-related content"),
    4: ("Nudity", "Report nudity content"),
    5: ("Violence", "Report violent content"),
    6: ("Hate", "Report hate speech"),
}

reason_ids = {
    "Spam": 1,
    "Self": 2,
    "Drugs": 3,
    "Nudity": 4,
    "Violence": 5,
    "Hate": 6,
}

def log_user_to_file(user_id, username):
    try:
        with open("users.txt", "a", encoding="utf-8") as f:
            f.write(f"{user_id} - {username}\n")
    except Exception as e:
        console.print(f"[red]Error logging user to file: {str(e)}[/red]")

def get_csrf_token(sessionid):
    try:
        if sessionid in session_cache:
            return session_cache[sessionid]
        
        r1 = get(
            "https://www.instagram.com/",
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/110.0",
            },
            cookies={"sessionid": sessionid},
            timeout=10
        )
        if "csrftoken" in r1.cookies:
            session_cache[sessionid] = r1.cookies["csrftoken"]
            return r1.cookies["csrftoken"]
        else:
            return None
    except Exception as e:
        return None

def validate_session(sessionid):
    try:
        csrf = get_csrf_token(sessionid)
        if csrf:
            test_req = get(
                "https://www.instagram.com/accounts/edit/",
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/110.0",
                },
                cookies={"sessionid": sessionid},
                timeout=10,
                allow_redirects=False
            )
            return test_req.status_code == 200, csrf
        return False, None
    except Exception as e:
        return False, None

def filter_sessions(sessions, user_id, callback_message_id):
    valid_sessions = []
    invalid_sessions = []
    total = len(sessions)
    
    progress_message = bot.send_message(user_id, f"Checking sessions... ({0}/{total})")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_session = {executor.submit(validate_session, session): session for session in sessions}
        
        completed = 0
        for future in concurrent.futures.as_completed(future_to_session):
            session = future_to_session[future]
            try:
                is_valid, csrf = future.result()
                if is_valid:
                    valid_sessions.append(session)
                    session_cache[session] = csrf
                else:
                    invalid_sessions.append(session)
            except Exception as e:
                invalid_sessions.append(session)
            
            completed += 1
            if completed % 5 == 0 or completed == total:
                try:
                    bot.edit_message_text(
                        f"Checking sessions... ({completed}/{total})",
                        user_id,
                        progress_message.message_id
                    )
                except:
                    pass
    
    result_message = f"Found {len(valid_sessions)} valid sessions\nExcluded {len(invalid_sessions)} invalid sessions"
    
    try:
        bot.edit_message_text(result_message, user_id, progress_message.message_id)
    except:
        bot.send_message(user_id, result_message)
    
    return valid_sessions

def report_instagram(target_id, sessionid, csrftoken, reportType):
    try:
        r3 = post(
            f"https://i.instagram.com/users/{target_id}/flag/",
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/110.0",
                "Host": "i.instagram.com",
                "cookie": f"sessionid={sessionid}",
                "X-CSRFToken": csrftoken,
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
            },
            data=f'source_name=&reason_id={reportType}&frx_context=',
            allow_redirects=False,
            timeout=15
        )
        return r3.status_code == 200 or r3.status_code == 302
    except Exception as e:
        return False

def get_random_report_type():
    report_type_id = random.choice(list(report_options.keys()))
    report_type, _ = report_options[report_type_id]
    reason_id = reason_ids[report_type]
    return report_type, reason_id

def start_reporting_process(user_id):
    target_id = user_data[user_id]['target_id']
    report_type = user_data[user_id].get('report_type')
    reason_id = user_data[user_id].get('reason_id')
    sleep_time = user_data[user_id]['sleep_time']
    valid_sessions = user_data[user_id]['valid_sessions']
    use_random_reports = user_data[user_id].get('use_random_reports', False)
    
    reports_per_session = user_data[user_id].get('reports_per_session', float('inf'))
    if len(valid_sessions) == 1:
        reports_per_session = float('inf')
    
    status_message = bot.send_message(
        user_id, 
        "Starting reporting process...", 
        parse_mode="HTML"
    )
    
    active_reports[user_id] = {
        'running': True,
        'status_message_id': status_message.message_id,
        'good_count': 0,
        'bad_count': 0,
        'invalid_sessions': [],
        'current_session_index': 0,
        'current_session': '',
        'use_random_reports': use_random_reports,
        'current_report_type': report_type,
        'last_report_type_change': '',
    }
    
    threading.Thread(target=reporting_thread, args=(user_id, target_id, report_type, reason_id, sleep_time, reports_per_session, valid_sessions, status_message.message_id, use_random_reports)).start()

def reporting_thread(user_id, target_id, report_type, reason_id, sleep_time, reports_per_session, valid_sessions, message_id, use_random_reports):
    report_data = active_reports[user_id]
    good_count = 0
    bad_count = 0
    invalid_sessions = []
    multiple_sessions = len(valid_sessions) > 1
    last_update_time = time.time()
    update_interval = 2
    current_session = ''
    current_report_type = report_type
    current_reason_id = reason_id
    
    try:
        while report_data['running'] and valid_sessions:
            for i, sessionid in enumerate(valid_sessions[:]):
                if sessionid in invalid_sessions:
                    continue
                
                report_data['current_session_index'] = i + 1
                report_data['current_session'] = sessionid
                current_session = sessionid
                
                csrftoken = get_csrf_token(sessionid)
                if not csrftoken:
                    bad_count += 1
                    invalid_sessions.append(sessionid)
                    if sessionid in valid_sessions:
                        valid_sessions.remove(sessionid)
                    
                    if time.time() - last_update_time >= update_interval:
                        update_status_message(user_id, good_count, bad_count, i+1, len(valid_sessions), f"Session {sessionid[:8]}... is invalid and has been removed")
                        last_update_time = time.time()
                    continue

                session_success = 0
                
                report_counter = 0
                while (reports_per_session == float('inf') or report_counter < reports_per_session) and report_data['running']:
                    try:
                        if use_random_reports:
                            previous_report_type = current_report_type
                            current_report_type, current_reason_id = get_random_report_type()
                            report_data['current_report_type'] = current_report_type
                            
                            if previous_report_type != current_report_type:
                                report_data['last_report_type_change'] = f"Report type changed: {previous_report_type} → {current_report_type}"
                        
                        if report_instagram(target_id, sessionid, csrftoken, current_reason_id):
                            good_count += 1
                            session_success += 1
                        else:
                            bad_count += 1
                            is_valid, _ = validate_session(sessionid)
                            if not is_valid:
                                invalid_sessions.append(sessionid)
                                if sessionid in valid_sessions:
                                    valid_sessions.remove(sessionid)
                                
                                if time.time() - last_update_time >= update_interval:
                                    update_status_message(user_id, good_count, bad_count, i+1, len(valid_sessions), f"Session {sessionid[:8]}... expired and has been removed")
                                    last_update_time = time.time()
                                break

                        if time.time() - last_update_time >= update_interval:
                            update_status_message(user_id, good_count, bad_count, i+1, len(valid_sessions))
                            last_update_time = time.time()
                        
                        if sleep_time > 0:
                            time.sleep(sleep_time)
                            
                        report_counter += 1
                        
                    except Exception as e:
                        bad_count += 1
                        break
                
                if reports_per_session != float('inf'):
                    update_status_message(user_id, good_count, bad_count, i+1, len(valid_sessions), f"Sent {session_success} reports from session {i+1}/{len(valid_sessions)}")
                else:
                    update_status_message(user_id, good_count, bad_count, i+1, len(valid_sessions), f"Sent {session_success} reports using single session")
                last_update_time = time.time()
            
            if not valid_sessions:
                update_status_message(user_id, good_count, bad_count, 0, 0, "No valid sessions remaining! Process stopped.")
                break
            
            if multiple_sessions and report_data['running']:
                update_status_message(
                    user_id, 
                    good_count, 
                    bad_count, 
                    1, 
                    len(valid_sessions), 
                    "Full cycle completed. Starting new cycle..."
                )
                time.sleep(3)
        
        report_data['good_count'] = good_count
        report_data['bad_count'] = bad_count
        
        session_display = current_session[:8] + "......" if current_session else "None"
        
        if use_random_reports:
            report_type_display = f"Random (last type: {current_report_type})"
        else:
            report_type_display = current_report_type
        
        final_message = f"<b>Final Report</b>\n\nSuccessful reports: <b>{good_count}</b>\nFailed reports: <b>{bad_count}</b>\nSession: <b>{session_display}</b>\nWait time between reports: <b>{sleep_time} seconds</b>\nTarget ID: <b>{target_id}</b>\nReport type: <b>{report_type_display}</b>\n\n<b>Process completed!</b>"
        
        try:
            bot.edit_message_text(
                final_message,
                user_id,
                message_id,
                parse_mode="HTML"
            )
        except:
            bot.send_message(user_id, final_message, parse_mode="HTML")
        
        user_states[user_id] = UserState.IDLE
        
    except Exception as e:
        error_message = f"Error during reporting process: {str(e)}"
        try:
            bot.edit_message_text(
                error_message,
                user_id,
                message_id
            )
        except:
            bot.send_message(user_id, error_message)
    
    finally:
        if user_id in active_reports:
            active_reports[user_id]['running'] = False
        if user_id in user_data and 'valid_sessions' in user_data[user_id]:
            del user_data[user_id]['valid_sessions']

def update_status_message(user_id, good_count, bad_count, current_session_idx, total_sessions, additional_info=None):
    if user_id not in active_reports:
        return
    
    report_data = active_reports[user_id]
    report_data['good_count'] = good_count
    report_data['bad_count'] = bad_count
    
    current_session = report_data.get('current_session', '')
    session_display = current_session[:8] + "......" if current_session else "None"
    
    use_random_reports = report_data.get('use_random_reports', False)
    current_report_type = report_data.get('current_report_type', 'Unknown')
    
    if use_random_reports:
        report_type_display = f"<b>{current_report_type}</b> (random mode)"
        report_type_change = report_data.get('last_report_type_change', '')
    else:
        report_type_display = f"<b>{current_report_type}</b>"
        report_type_change = ""
    
    status_text = f"<b>Reporting Status</b>\n\nSuccessful reports: <b>{good_count}</b>\nFailed reports: <b>{bad_count}</b>\nCurrent session: <b>{session_display}</b>\nReport type: {report_type_display}\n"
    
    if report_type_change:
        status_text += f"<i>{report_type_change}</i>\n"
    
    if total_sessions > 0:
        status_text += f"Session progress: <b>{current_session_idx}/{total_sessions}</b>\n"
    
    if additional_info:
        status_text += f"\n<i>{additional_info}</i>\n"
    
    status_text += "\n<i>You can stop the process at any time by sending /stop</i>"
    
    try:
        bot.edit_message_text(
            status_text,
            user_id,
            report_data['status_message_id'],
            parse_mode="HTML"
        )
    except:
        pass

def create_sessions_list(user_id, sessions_text):
    sessions = sessions_text.strip().split('\n')
    sessions = [s.strip() for s in sessions if s.strip()]
    
    if not sessions:
        bot.send_message(user_id, "No sessions provided. Please try again with at least one session.")
        return False
    
    with open("sessions.txt", "w", encoding="utf-8") as f:
        for session in sessions:
            f.write(f"{session}\n")
    
    bot.send_message(user_id, f"Your sessions have been saved to sessions.txt.\nTotal sessions saved: {len(sessions)}\n\nYou can now use /report to start the reporting process.")
    
    with open("sessions.txt", "rb") as f:
        bot.send_document(user_id, f, caption="sessions.txt")
    
    return True

def get_user_identifier(user):
    user_id = user.id
    username = user.username or "Unknown"
    return f"{user_id} - {username}"

@bot.message_handler(commands=['start'])
def handle_start(message):
    user_id = message.from_user.id
    username = message.from_user.username or "Unknown"
    user_identifier = get_user_identifier(message.from_user)
    
    console.print(f"[green]New user: {user_identifier}[/green]")
    log_user_to_file(user_id, username)
    
    bot.send_message(user_id, "Welcome to Instagram Report Bot\n\nAvailable commands:\n/report - Start reporting process\n/create_sessions - Create sessions list\n/stop - Stop current reporting process\n/status - Check current reporting status\n/help - Show help information\n\nTo begin, send your sessions.txt file or use the /report command")
    user_states[user_id] = UserState.IDLE

@bot.message_handler(commands=['help'])
def handle_help(message):
    user_id = message.from_user.id
    help_message = "<b>Help Guide</b>\n\n1. Send a sessions.txt file containing Instagram sessions\n2. Use /report to start the reporting process\n3. Follow the instructions to enter target ID and report type\n4. You can stop the process at any time using /stop\n\n<b>Available Report Types:</b>\n1 - Spam\n2 - Self-harm\n3 - Drugs\n4 - Nudity\n5 - Violence\n6 - Hate\n7 - Random (changes with each report)\n\n<b>Creating Sessions List:</b>\n• Use /create_sessions to create a sessions list\n• Enter the sessions, one per line\n• The bot will save them to a sessions.txt file\n\n<b>Important Notes:</b>\n• Sessions are only used during the current reporting process and are not stored\n• You will need to send your sessions.txt file for each new reporting process\n• Do not use very short wait times to avoid bans\n• Results are updated in real-time during reporting"
    bot.send_message(user_id, help_message, parse_mode="HTML")

@bot.message_handler(commands=['report'])
def handle_report(message):
    user_id = message.from_user.id
    user_identifier = get_user_identifier(message.from_user)
    user_states[user_id] = UserState.AWAITING_TARGET_ID
    
    if user_id in user_data and 'valid_sessions' in user_data[user_id] and user_data[user_id]['valid_sessions']:
        valid_sessions = user_data[user_id]['valid_sessions']
        bot.send_message(
            user_id, 
            f"Found {len(valid_sessions)} sessions in memory.\n\nPlease enter the target ID:"
        )
    else:
        bot.send_message(
            user_id, 
            "You must send a sessions file to start the reporting process!"
        )
        user_states[user_id] = UserState.IDLE

@bot.message_handler(commands=['create_sessions'])
def handle_create_sessions(message):
    user_id = message.from_user.id
    user_identifier = get_user_identifier(message.from_user)
    
    console.print(f"[yellow]User {user_identifier} requested to create sessions list[/yellow]")
    
    welcome_message = "<b>Create Sessions List</b>\n\nThis command allows you to create a sessions.txt file by entering sessions directly in the chat.\n\nPlease enter the sessions, one per line:"
    
    bot.send_message(user_id, welcome_message, parse_mode="HTML")
    user_states[user_id] = UserState.AWAITING_SESSIONS_INPUT

@bot.message_handler(commands=['stop'])
def handle_stop(message):
    user_id = message.from_user.id
    
    if user_id in active_reports and active_reports[user_id]['running']:
        active_reports[user_id]['running'] = False
        bot.send_message(user_id, "Stopping the reporting process.")
        
        good_count = active_reports[user_id]['good_count']
        bad_count = active_reports[user_id]['bad_count']
        current_session = active_reports[user_id].get('current_session', '')
        session_display = current_session[:8] + "......" if current_session else "None"
        
        use_random_reports = active_reports[user_id].get('use_random_reports', False)
        current_report_type = active_reports[user_id].get('current_report_type', 'Unknown')
        
        if use_random_reports:
            report_type_display = f"{current_report_type} (random, last type: {current_report_type})"
        else:
            report_type_display = current_report_type
        
        stats_message = f"<b>Process Statistics</b>\n\nSuccessful reports: <b>{good_count}</b>\nFailed reports: <b>{bad_count}</b>\nSession: <b>{session_display}</b>\nReport type: <b>{report_type_display}</b>\nTotal: <b>{good_count + bad_count}</b>\n\n<b>Process stopped successfully!</b>"
        
        bot.send_message(user_id, stats_message, parse_mode="HTML")
        user_states[user_id] = UserState.IDLE
        
        if user_id in user_data and 'valid_sessions' in user_data[user_id]:
            del user_data[user_id]['valid_sessions']
    else:
        bot.send_message(user_id, "No active reporting process.")

@bot.message_handler(commands=['status'])
def handle_status(message):
    user_id = message.from_user.id
    
    if user_id in active_reports and active_reports[user_id]['running']:
        good_count = active_reports[user_id]['good_count']
        bad_count = active_reports[user_id]['bad_count']
        current_session = active_reports[user_id].get('current_session', '')
        session_display = current_session[:8] + "......" if current_session else "None"
        
        use_random_reports = active_reports[user_id].get('use_random_reports', False)
        current_report_type = active_reports[user_id].get('current_report_type', 'Unknown')
        
        if use_random_reports:
            report_type_display = f"{current_report_type} (random mode)"
        else:
            report_type_display = current_report_type
        
        status_message = f"<b>Current Process Status</b>\n\nSuccessful reports: <b>{good_count}</b>\nFailed reports: <b>{bad_count}</b>\nCurrent session: <b>{session_display}</b>\nReport type: <b>{report_type_display}</b>\nTotal: <b>{good_count + bad_count}</b>\n\n<i>Process is running... You can stop it using /stop</i>"
        
        bot.send_message(user_id, status_message, parse_mode="HTML")
    else:
        bot.send_message(user_id, "No active reporting process.")

@bot.message_handler(content_types=['document'])
def handle_document(message):
    user_id = message.from_user.id
    username = message.from_user.username or "Unknown"
    user_identifier = get_user_identifier(message.from_user)
    
    if message.document.file_name.lower() != 'sessions.txt':
        bot.send_message(user_id, "Please send a file named sessions.txt only.")
        return
    
    console.print(f"[yellow]User {user_identifier} uploaded sessions file[/yellow]")
    log_user_to_file(user_id, username)
    
    file_info = bot.get_file(message.document.file_id)
    downloaded_file = bot.download_file(file_info.file_path)
    
    sessions = downloaded_file.decode('utf-8').splitlines()
    
    if not sessions:
        bot.send_message(user_id, "Sessions file is empty! Please send a valid file.")
        return
    
    if user_id not in user_data:
        user_data[user_id] = {}
    
    bot.send_message(user_id, f"Checking sessions... (0/{len(sessions)})")
    valid_sessions = filter_sessions(sessions, user_id, 0)
    
    if not valid_sessions:
        bot.send_message(user_id, "No valid sessions found! Please check your sessions file.")
        return
    
    user_data[user_id]['valid_sessions'] = valid_sessions
    bot.send_message(user_id, f"Found {len(valid_sessions)} valid sessions.\nUse /report to start the reporting process.")

@bot.message_handler(func=lambda message: user_states.get(message.from_user.id) == UserState.AWAITING_SESSIONS_INPUT)
def handle_sessions_input(message):
    user_id = message.from_user.id
    sessions_text = message.text
    
    if create_sessions_list(user_id, sessions_text):
        with open("sessions.txt", "r", encoding="utf-8") as f:
            sessions = [line.strip() for line in f.readlines()]
        
        valid_sessions = filter_sessions(sessions, user_id, 0)
        
        if user_id not in user_data:
            user_data[user_id] = {}
        
        user_data[user_id]['valid_sessions'] = valid_sessions
        
        user_states[user_id] = UserState.IDLE
        
        if valid_sessions:
            bot.send_message(
                user_id, 
                f"Successfully loaded {len(valid_sessions)} valid sessions.\n\nYou can now use /report to start the reporting process."
            )
        else:
            bot.send_message(
                user_id, 
                "No valid sessions found. Please try again with different sessions."
            )

@bot.message_handler(func=lambda message: user_states.get(message.from_user.id) == UserState.AWAITING_TARGET_ID)
def handle_target_id_input(message):
    user_id = message.from_user.id
    text = message.text.strip()
    
    if not text.isdigit():
        bot.send_message(user_id, "Target ID must be a number only. Please enter a valid ID:")
        return
            
    if user_id not in user_data:
        user_data[user_id] = {}
    user_data[user_id]['target_id'] = text
    
    markup = types.InlineKeyboardMarkup()
    for key, (value, desc) in report_options.items():
        button_text = f"{key}. {value} - {desc}"
        markup.add(types.InlineKeyboardButton(button_text, callback_data=f"report_type_{key}"))
    
    markup.add(types.InlineKeyboardButton("Random - Random report types for each report", callback_data="report_type_random"))
    
    bot.send_message(
        user_id, 
        "Choose report type:", 
        reply_markup=markup
    )
    
    user_states[user_id] = UserState.AWAITING_REPORT_TYPE

@bot.callback_query_handler(func=lambda call: call.data.startswith('report_type_'))
def handle_report_type_callback(call):
    user_id = call.from_user.id
    
    if user_states.get(user_id) != UserState.AWAITING_REPORT_TYPE:
        return
    
    report_type_data = call.data.replace('report_type_', '')
    
    if report_type_data == 'random':
        user_data[user_id]['use_random_reports'] = True
        report_type, reason_id = get_random_report_type()
    else:
        report_id = int(report_type_data)
        report_type, _ = report_options[report_id]
        reason_id = report_id
        user_data[user_id]['use_random_reports'] = False
    
    user_data[user_id]['report_type'] = report_type
    user_data[user_id]['reason_id'] = reason_id
    
    if report_type_data == 'random':
        bot.edit_message_text(
            f"Selected report type: Random (cycles through all types)",
            user_id,
            call.message.message_id
        )
    else:
        bot.edit_message_text(
            f"Selected report type: {report_type}",
            user_id,
            call.message.message_id
        )
    
    if len(user_data[user_id]['valid_sessions']) > 1:
        bot.send_message(
            user_id, 
            "Please enter the number of reports per session (or 'inf' for unlimited):"
        )
        user_states[user_id] = UserState.AWAITING_REPORTS_PER_SESSION
    else:
        bot.send_message(
            user_id, 
            "Please enter the sleep time between reports (in seconds):"
        )
        user_states[user_id] = UserState.AWAITING_SLEEP_TIME

@bot.message_handler(func=lambda message: user_states.get(message.from_user.id) == UserState.AWAITING_REPORTS_PER_SESSION)
def handle_reports_per_session_input(message):
    user_id = message.from_user.id
    text = message.text.strip().lower()
    
    if text == 'inf':
        reports_per_session = float('inf')
    else:
        try:
            reports_per_session = int(text)
            if reports_per_session <= 0:
                bot.send_message(
                    user_id, 
                    "Please enter a positive number or 'inf'. Enter a valid number:"
                )
                return
        except ValueError:
            bot.send_message(
                user_id, 
                "Invalid input. Please enter a number or 'inf'."
            )
            return
    
    user_data[user_id]['reports_per_session'] = reports_per_session
    
    bot.send_message(user_id, "Enter sleep time between reports (in seconds):")
    user_states[user_id] = UserState.AWAITING_SLEEP_TIME

@bot.message_handler(func=lambda message: user_states.get(message.from_user.id) == UserState.AWAITING_SLEEP_TIME)
def handle_sleep_time_input(message):
    user_id = message.from_user.id
    text = message.text.strip()
    
    try:
        sleep_time = float(text)
        if sleep_time < 0:
            bot.send_message(
                user_id, 
                "Please enter a valid number or decimal. Enter a valid time:"
            )
            return
    except ValueError:
        bot.send_message(
            user_id, 
            "Invalid input. Please enter a valid number or decimal."
        )
        return
    
    user_data[user_id]['sleep_time'] = sleep_time
    
    target_id = user_data[user_id]['target_id']
    report_type = user_data[user_id].get('report_type', 'Random')
    valid_sessions = user_data[user_id]['valid_sessions']
    use_random_reports = user_data[user_id].get('use_random_reports', False)
    
    if use_random_reports:
        report_type_display = "Random (will change with each report)"
    else:
        report_type_display = report_type
    
    reports_per_session_text = ""
    if len(valid_sessions) > 1 and 'reports_per_session' in user_data[user_id]:
        reports_per_session = user_data[user_id]['reports_per_session']
        reports_per_session_text = f"Reports per session: <b>{reports_per_session}</b>\n"
    
    summary = f"<b>Settings Summary</b>\n\nTarget ID: <b>{target_id}</b>\nReport type: <b>{report_type_display}</b>\nSessions count: <b>{len(valid_sessions)}</b>\n{reports_per_session_text}Sleep time: <b>{sleep_time} seconds</b>\n\nReady to start reporting process. Confirm?"
    
    markup = types.InlineKeyboardMarkup()
    markup.add(types.InlineKeyboardButton("Start", callback_data="confirm_report_start"))
    markup.add(types.InlineKeyboardButton("Cancel", callback_data="cancel_report"))
    
    bot.send_message(
        user_id, 
        summary, 
        reply_markup=markup,
        parse_mode="HTML"
    )

@bot.callback_query_handler(func=lambda call: call.data == "confirm_report_start")
def handle_confirm_report_start(call):
    user_id = call.from_user.id
    
    bot.edit_message_text(
        "Starting reporting process...",
        user_id,
        call.message.message_id
    )
    
    user_states[user_id] = UserState.REPORTING
    start_reporting_process(user_id)

@bot.callback_query_handler(func=lambda call: call.data == "cancel_report")
def handle_cancel_report(call):
    user_id = call.from_user.id
    
    bot.edit_message_text(
        "Reporting process cancelled.",
        user_id,
        call.message.message_id
    )
    
    user_states[user_id] = UserState.IDLE

@bot.message_handler(func=lambda message: True)
def handle_messages(message):
    user_id = message.from_user.id
    
    if user_id not in user_states:
        user_states[user_id] = UserState.IDLE
    
    if user_states[user_id] == UserState.IDLE:
        bot.send_message(user_id, "Unknown command. Use /help to see available commands.")

if __name__ == "__main__":
    # Run as Telegram bot
    console.print("[green]Bot started![/green]")
    bot.polling(none_stop=True)
