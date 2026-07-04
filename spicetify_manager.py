"""
=====================================================
 Spicetify Manager — PySide6 Edition
 С поддержкой переключения языка RU/EN
=====================================================
"""
import sys,subprocess,os,threading,time,re,json,ssl,ctypes
from ctypes import wintypes
from pathlib import Path
from urllib.request import urlopen,Request
from urllib.error import URLError,HTTPError
try:
    _ssl_context=ssl.create_default_context()
except:
    _ssl_context=ssl._create_unverified_context()
try:
    import certifi
    _ssl_context.load_verify_locations(certifi.where())
except:
    _ssl_context=ssl._create_unverified_context()
import warnings
warnings.filterwarnings('ignore',message='Unverified HTTPS request')
try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests=None
from PySide6.QtWidgets import (QApplication,QMainWindow,QWidget,QVBoxLayout,QHBoxLayout,QLabel,QPushButton,QFrame,QGraphicsOpacityEffect,QSizePolicy,QDialog,QScrollArea)
from PySide6.QtCore import Qt,QTimer,Signal,QPropertyAnimation,QEasingCurve,Property
from PySide6.QtGui import QFont,QColor,QPalette,QPainter,QIcon,QPixmap,QPen,QBrush,QLinearGradient
from PySide6.QtCore import QPointF,QRectF
import random,math
from PySide6.QtSvg import QSvgRenderer
import resources_rc

FPS_75=13
HOVER_SPEED=20
APP_VERSION="1.9"
GITHUB_OWNER="on1felix"
GITHUB_REPO="spicetify-manager"
GITHUB_API_URL=f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/releases/latest"

SETTINGS_DIR=os.path.join(os.getenv("APPDATA",os.path.expanduser("~")),"SpicetifyManager")
SETTINGS_FILE=os.path.join(SETTINGS_DIR,"settings.json")
POWERSHELL_TRUSTLEVEL=0x20000
if sys.platform=="win32":
    _kernel32=ctypes.WinDLL("kernel32",use_last_error=True)
    _kernel32.CloseHandle.argtypes=[wintypes.HANDLE];_kernel32.CloseHandle.restype=wintypes.BOOL
    _kernel32.GetExitCodeProcess.argtypes=[wintypes.HANDLE,ctypes.POINTER(wintypes.DWORD)];_kernel32.GetExitCodeProcess.restype=wintypes.BOOL
    _kernel32.WaitForSingleObject.argtypes=[wintypes.HANDLE,wintypes.DWORD];_kernel32.WaitForSingleObject.restype=wintypes.DWORD

def ensure_settings_dir():
    if not os.path.exists(SETTINGS_DIR):
        try:os.makedirs(SETTINGS_DIR)
        except:pass

class STARTUPINFO(ctypes.Structure):
    _fields_=[("cb",wintypes.DWORD),("lpReserved",wintypes.LPWSTR),("lpDesktop",wintypes.LPWSTR),("lpTitle",wintypes.LPWSTR),("dwX",wintypes.DWORD),("dwY",wintypes.DWORD),("dwXSize",wintypes.DWORD),("dwYSize",wintypes.DWORD),("dwXCountChars",wintypes.DWORD),("dwYCountChars",wintypes.DWORD),("dwFillAttribute",wintypes.DWORD),("dwFlags",wintypes.DWORD),("wShowWindow",wintypes.WORD),("cbReserved2",wintypes.WORD),("lpReserved2",ctypes.c_void_p),("hStdInput",wintypes.HANDLE),("hStdOutput",wintypes.HANDLE),("hStdError",wintypes.HANDLE)]

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_=[("hProcess",wintypes.HANDLE),("hThread",wintypes.HANDLE),("dwProcessId",wintypes.DWORD),("dwThreadId",wintypes.DWORD)]

class TrustlevelProcess:
    def __init__(self,process_handle,thread_handle,process_id):
        self._process_handle=process_handle;self._thread_handle=thread_handle;self.pid=process_id;self.returncode=None
        if self._thread_handle:_kernel32.CloseHandle(self._thread_handle);self._thread_handle=None
    def poll(self):
        if self.returncode is not None:return self.returncode
        code=wintypes.DWORD()
        if not _kernel32.GetExitCodeProcess(self._process_handle,ctypes.byref(code)):raise ctypes.WinError(ctypes.get_last_error())
        if code.value==259:return None
        self.returncode=code.value;self.close();return self.returncode
    def wait(self,timeout=None):
        if self.returncode is not None:return self.returncode
        milliseconds=0xFFFFFFFF if timeout is None else int(timeout*1000)
        result=_kernel32.WaitForSingleObject(self._process_handle,milliseconds)
        if result==0x102:raise subprocess.TimeoutExpired(self.pid,timeout)
        if result==0xFFFFFFFF:raise ctypes.WinError(ctypes.get_last_error())
        return self.poll()
    def close(self):
        if self._thread_handle:_kernel32.CloseHandle(self._thread_handle);self._thread_handle=None
        if self._process_handle:_kernel32.CloseHandle(self._process_handle);self._process_handle=None
    def __del__(self):
        try:self.close()
        except:pass

def start_trustlevel_process(command_line,creationflags=0):
    if sys.platform!="win32":return subprocess.Popen(command_line,creationflags=creationflags)
    advapi32=ctypes.WinDLL("advapi32",use_last_error=True)
    advapi32.SaferCreateLevel.argtypes=[wintypes.DWORD,wintypes.DWORD,wintypes.DWORD,ctypes.POINTER(wintypes.HANDLE),ctypes.c_void_p];advapi32.SaferCreateLevel.restype=wintypes.BOOL
    advapi32.SaferComputeTokenFromLevel.argtypes=[wintypes.HANDLE,wintypes.HANDLE,ctypes.POINTER(wintypes.HANDLE),wintypes.DWORD,ctypes.c_void_p];advapi32.SaferComputeTokenFromLevel.restype=wintypes.BOOL
    advapi32.SaferCloseLevel.argtypes=[wintypes.HANDLE];advapi32.SaferCloseLevel.restype=wintypes.BOOL
    advapi32.CreateProcessAsUserW.argtypes=[wintypes.HANDLE,wintypes.LPCWSTR,wintypes.LPWSTR,ctypes.c_void_p,ctypes.c_void_p,wintypes.BOOL,wintypes.DWORD,ctypes.c_void_p,wintypes.LPCWSTR,ctypes.POINTER(STARTUPINFO),ctypes.POINTER(PROCESS_INFORMATION)];advapi32.CreateProcessAsUserW.restype=wintypes.BOOL
    level_handle=wintypes.HANDLE();token_handle=wintypes.HANDLE();process_info=PROCESS_INFORMATION();startup_info=STARTUPINFO();startup_info.cb=ctypes.sizeof(startup_info)
    try:
        if not advapi32.SaferCreateLevel(1,POWERSHELL_TRUSTLEVEL,0,ctypes.byref(level_handle),None):raise ctypes.WinError(ctypes.get_last_error())
        if not advapi32.SaferComputeTokenFromLevel(level_handle,None,ctypes.byref(token_handle),0,None):raise ctypes.WinError(ctypes.get_last_error())
        command_buffer=ctypes.create_unicode_buffer(command_line)
        if not advapi32.CreateProcessAsUserW(token_handle,None,command_buffer,None,None,False,creationflags,None,None,ctypes.byref(startup_info),ctypes.byref(process_info)):raise ctypes.WinError(ctypes.get_last_error())
        return TrustlevelProcess(process_info.hProcess,process_info.hThread,process_info.dwProcessId)
    finally:
        if token_handle:_kernel32.CloseHandle(token_handle)
        if level_handle:advapi32.SaferCloseLevel(level_handle)

def build_powershell_cmd(command):
    return subprocess.list2cmdline(['powershell.exe','-NoProfile','-ExecutionPolicy','Bypass','-Command',command])

def start_powershell_trustlevel(command,creationflags=0):
    return start_trustlevel_process(build_powershell_cmd(command),creationflags)

def run_powershell_trustlevel(command,timeout=None,creationflags=0):
    process=start_powershell_trustlevel(command,creationflags)
    return process.wait(timeout)

TRANSLATIONS={
    "ru":{
        "app_title":"SPICETIFY MANAGER","window_title":"Spicetify Manager",
        "btn_install":"Установить","btn_reinstall":"Починить","btn_update":"Обновить","btn_check":"Проверить","btn_delete":"Удалить","btn_cancel":"Отмена","btn_continue":"Продолжить","btn_close":"Закрыть","btn_open_folder":"Открыть папку","btn_delete_old_open":"Удалить старую и открыть папку",
        "status_loading":"Загрузка информации...","status_installed":"Статус: Установлен","status_not_installed":"Статус: Не установлен","status_update_available":"Доступно обновление!","status_version":"Версия","status_latest":"Последняя","status_available_version":"Доступная версия",
        "console_check_header":"ПРОВЕРКА SPICETIFY","console_install_header":"УСТАНОВКА SPICETIFY","console_reinstall_header":"ПЕРЕУСТАНОВКА SPICETIFY","console_update_header":"ОБНОВЛЕНИЕ SPICETIFY","console_delete_header":"УДАЛЕНИЕ SPICETIFY",
        "console_checking_version":"Проверка установленной версии...","console_version_installed":"Установлена версия:","console_spicetify_found_no_response":"Spicetify найден, но не отвечает","console_spicetify_damaged":"Spicetify поврежден или не работает","console_spicetify_not_installed":"Spicetify не установлен","console_checking_latest":"Проверка последней версии...","console_latest_version":"Последняя версия:","console_update_available":"Доступно обновление!","console_latest_installed":"У вас установлена последняя версия","console_fetch_error":"Не удалось получить информацию о версиях","console_error":"Ошибка:",
        "console_already_installed":"Spicetify уже установлен!","console_starting_script":"Запуск установочного скрипта...","console_powershell_confirm":"Откроется окно PowerShell для подтверждения","console_waiting_install":"Ожидание завершения установки...","console_waiting_reinstall":"Ожидание завершения переустановки...","console_waiting_update":"Ожидание завершения обновления...","console_window_closed":"Окно установки закрыто","console_reinstall_window_closed":"Окно переустановки закрыто","console_update_window_closed":"Окно обновления закрыто","console_install_success":"Spicetify успешно установлен!","console_reinstall_success":"Spicetify успешно переустановлен!","console_update_complete":"Обновление завершено!","console_install_failed":"Не удалось установить Spicetify","console_spicetify_not_found":"Spicetify не найден","console_install_first":"Сначала установите Spicetify!","console_starting_update":"Запуск обновления...",
        "console_starting_delete":"Запуск процесса удаления...","console_restoring_spotify":"Восстановление оригинального Spotify...","console_spotify_restored":"Spotify восстановлен в оригинальное состояние","console_restore_error":"Ошибка при восстановлении:","console_deleting_files":"Удаление файлов Spicetify...","console_deleted":"Удалено:","console_folder_not_found":"Папка не найдена:","console_delete_appdata_error":"Ошибка при удалении APPDATA:","console_delete_localappdata_error":"Ошибка при удалении LOCALAPPDATA:","console_delete_success":"Spicetify успешно удален!","console_files_cleaned":"Все файлы и настройки очищены",
        "dialog_confirm_install":"Подтверждение установки","dialog_confirm_reinstall":"Подтверждение переустановки","dialog_confirm_delete":"Подтверждение удаления","dialog_install_question":"Вы действительно хотите установить Spicetify?","dialog_reinstall_question":"Вы действительно хотите переустановить Spicetify?","dialog_delete_question":"Вы действительно хотите удалить Spicetify?\nЭто действие нельзя отменить!",
        "app_update_available":"Доступно обновление!","app_update_downloading":"Скачивание обновления","app_update_downloaded":"Обновление скачано!","app_update_error":"Ошибка скачивания","app_no_updates":"Обновлений нет","app_latest_version":"У вас установлена последняя версия!","app_checking_updates":"Проверка обновлений...","app_please_wait":"Подождите, идёт проверка...","app_current_version":"Текущая версия:","app_replace_exe":"Замените старый .exe на новый!","app_click_to_delete":"Нажмите для удаления старой версии\nи перехода к папке с новой!","app_preparing":"Подготовка...",
        "loading_install":"Установка Spicetify...","loading_reinstall":"Переустановка Spicetify...","loading_update":"Обновление Spicetify...","loading_delete":"Удаление Spicetify...",
        "footer_copyright":"© 2026 OOO Spicetify. Все права защищены.","footer_unofficial":"Неофициальное приложение. Официальный сайт Spicetify:",
        "size_mb":"МБ",
    },
    "en":{
        "app_title":"SPICETIFY MANAGER","window_title":"Spicetify Manager",
        "btn_install":"Install","btn_reinstall":"Repair","btn_update":"Update","btn_check":"Check","btn_delete":"Delete","btn_cancel":"Cancel","btn_continue":"Continue","btn_close":"Close","btn_open_folder":"Open folder","btn_delete_old_open":"Delete old and open folder",
        "status_loading":"Loading information...","status_installed":"Status: Installed","status_not_installed":"Status: Not installed","status_update_available":"Update available!","status_version":"Version","status_latest":"Latest","status_available_version":"Available version",
        "console_check_header":"CHECKING SPICETIFY","console_install_header":"INSTALLING SPICETIFY","console_reinstall_header":"REINSTALLING SPICETIFY","console_update_header":"UPDATING SPICETIFY","console_delete_header":"REMOVING SPICETIFY",
        "console_checking_version":"Checking installed version...","console_version_installed":"Installed version:","console_spicetify_found_no_response":"Spicetify found but not responding","console_spicetify_damaged":"Spicetify is damaged or not working","console_spicetify_not_installed":"Spicetify is not installed","console_checking_latest":"Checking latest version...","console_latest_version":"Latest version:","console_update_available":"Update available!","console_latest_installed":"You have the latest version installed","console_fetch_error":"Failed to get version information","console_error":"Error:",
        "console_already_installed":"Spicetify is already installed!","console_starting_script":"Starting installation script...","console_powershell_confirm":"PowerShell window will open for confirmation","console_waiting_install":"Waiting for installation to complete...","console_waiting_reinstall":"Waiting for reinstallation to complete...","console_waiting_update":"Waiting for update to complete...","console_window_closed":"Installation window closed","console_reinstall_window_closed":"Reinstallation window closed","console_update_window_closed":"Update window closed","console_install_success":"Spicetify installed successfully!","console_reinstall_success":"Spicetify reinstalled successfully!","console_update_complete":"Update complete!","console_install_failed":"Failed to install Spicetify","console_spicetify_not_found":"Spicetify not found","console_install_first":"Install Spicetify first!","console_starting_update":"Starting update...",
        "console_starting_delete":"Starting removal process...","console_restoring_spotify":"Restoring original Spotify...","console_spotify_restored":"Spotify restored to original state","console_restore_error":"Error during restore:","console_deleting_files":"Deleting Spicetify files...","console_deleted":"Deleted:","console_folder_not_found":"Folder not found:","console_delete_appdata_error":"Error deleting APPDATA:","console_delete_localappdata_error":"Error deleting LOCALAPPDATA:","console_delete_success":"Spicetify removed successfully!","console_files_cleaned":"All files and settings cleared",
        "dialog_confirm_install":"Confirm installation","dialog_confirm_reinstall":"Confirm reinstallation","dialog_confirm_delete":"Confirm removal","dialog_install_question":"Do you really want to install Spicetify?","dialog_reinstall_question":"Do you really want to reinstall Spicetify?","dialog_delete_question":"Do you really want to remove Spicetify?\nThis action cannot be undone!",
        "app_update_available":"Update available!","app_update_downloading":"Downloading update","app_update_downloaded":"Update downloaded!","app_update_error":"Download error","app_no_updates":"No updates","app_latest_version":"You have the latest version!","app_checking_updates":"Checking for updates...","app_please_wait":"Please wait, checking...","app_current_version":"Current version:","app_replace_exe":"Replace the old .exe with the new one!","app_click_to_delete":"Click to delete old version\nand go to folder with new one!","app_preparing":"Preparing...",
        "loading_install":"Installing Spicetify...","loading_reinstall":"Reinstalling Spicetify...","loading_update":"Updating Spicetify...","loading_delete":"Removing Spicetify...",
        "footer_copyright":"© 2026 OOO Spicetify. All rights reserved.","footer_unofficial":"Unofficial app. Official Spicetify website:",
        "size_mb":"MB",
    }
}

def load_settings():
    try:
        if os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE,'r',encoding='utf-8') as f:return json.load(f)
    except:pass
    return {"language":"en"}

def save_settings(settings):
    ensure_settings_dir()
    try:
        with open(SETTINGS_FILE,'w',encoding='utf-8') as f:json.dump(settings,f,ensure_ascii=False,indent=2)
    except:pass

_current_language=None

def get_current_language():
    global _current_language
    if _current_language is None:_current_language=load_settings().get("language","ru")
    return _current_language

def set_current_language(lang):
    global _current_language
    _current_language=lang
    settings=load_settings()
    settings["language"]=lang
    save_settings(settings)

def get_text(key,lang=None):
    if lang is None:lang=get_current_language()
    return TRANSLATIONS.get(lang,TRANSLATIONS["ru"]).get(key,key)

def check_app_update():
    try:
        if requests:
            r=requests.get(GITHUB_API_URL,timeout=10,headers={'User-Agent':'Spicetify-Manager-Updater'},verify=False)
            r.raise_for_status();data=r.json()
        else:
            req=Request(GITHUB_API_URL,headers={'User-Agent':'Spicetify-Manager-Updater'})
            with urlopen(req,timeout=10,context=_ssl_context) as resp:data=json.loads(resp.read().decode('utf-8'))
        latest_version=data.get('tag_name','').replace('v','')
        download_url=None
        for asset in data.get('assets',[]):
            if asset['name'].endswith('.exe'):download_url=asset['browser_download_url'];break
        is_update=latest_version and latest_version!=APP_VERSION and compare_versions(latest_version,APP_VERSION)>0
        return {'current':APP_VERSION,'latest':latest_version,'update_available':is_update,'download_url':download_url,'release_notes':data.get('body',''),'release_name':data.get('name','')}
    except:return None

def compare_versions(v1,v2):
    try:
        parts1=[int(x) for x in v1.split('.')];parts2=[int(x) for x in v2.split('.')]
        while len(parts1)<len(parts2):parts1.append(0)
        while len(parts2)<len(parts1):parts2.append(0)
        for p1,p2 in zip(parts1,parts2):
            if p1>p2:return 1
            elif p1<p2:return -1
        return 0
    except:return 0


# ============================================================
# ПЕРЕКЛЮЧАТЕЛЬ ЯЗЫКА
# ============================================================

class LanguageToggle(QWidget):
    language_changed=Signal(str)
    def __init__(self,parent=None):
        super().__init__(parent)
        self.setFixedSize(52,22);self.setCursor(Qt.PointingHandCursor)
        self._enabled=True;self._hover_ru=False;self._hover_en=False
        self._ru_brightness=0.0;self._en_brightness=0.0
        self.setMouseTracking(True)
        self._is_english=get_current_language()=="en"
        self._hover_timer=QTimer();self._hover_timer.timeout.connect(self._animate_hover);self._hover_timer.start(HOVER_SPEED)
    def _animate_hover(self):
        changed=False
        if self._hover_ru and self._enabled and self._is_english:
            if self._ru_brightness<1.0:self._ru_brightness=min(1.0,self._ru_brightness+0.15);changed=True
        else:
            if self._ru_brightness>0.0:self._ru_brightness=max(0.0,self._ru_brightness-0.15);changed=True
        if self._hover_en and self._enabled and not self._is_english:
            if self._en_brightness<1.0:self._en_brightness=min(1.0,self._en_brightness+0.15);changed=True
        else:
            if self._en_brightness>0.0:self._en_brightness=max(0.0,self._en_brightness-0.15);changed=True
        if changed:self.update()
    def setEnabled(self,enabled):self._enabled=enabled;self.setCursor(Qt.PointingHandCursor if enabled else Qt.ForbiddenCursor);self.update()
    def isEnabled(self):return self._enabled
    def mouseMoveEvent(self,event):
        if not self._enabled:self._hover_ru=self._hover_en=False;return
        x=event.position().x();w=self.width()
        self._hover_ru=x<w/2;self._hover_en=x>=w/2
    def leaveEvent(self,event):self._hover_ru=self._hover_en=False
    def mousePressEvent(self,event):
        if event.button()==Qt.LeftButton and self._enabled:
            x=event.position().x();w=self.width()
            if x<w/2 and self._is_english:self._is_english=False;self.language_changed.emit("ru")
            elif x>=w/2 and not self._is_english:self._is_english=True;self.language_changed.emit("en")
    def paintEvent(self,event):
        painter=QPainter(self);painter.setRenderHint(QPainter.Antialiasing);painter.setRenderHint(QPainter.TextAntialiasing)
        w,h=self.width(),self.height()
        if self._enabled:painter.setPen(QPen(QColor(60,60,65),1));painter.setBrush(QColor(25,25,30,200))
        else:painter.setPen(QPen(QColor(40,40,45),1));painter.setBrush(QColor(20,20,25,150))
        painter.drawRoundedRect(0,0,w,h,4,4)
        painter.setPen(QPen(QColor(60,60,65) if self._enabled else QColor(40,40,45),1))
        painter.drawLine(int(w/2),4,int(w/2),h-4)
        font=QFont("Segoe UI",8,QFont.Bold);painter.setFont(font)
        if self._is_english:
            base_gray=80;hr,hg,hb=140,200,160
            r=int(base_gray+(hr-base_gray)*self._ru_brightness);g=int(base_gray+(hg-base_gray)*self._ru_brightness);b=int(base_gray+(hb-base_gray)*self._ru_brightness)
            painter.setPen(QColor(r,g,b) if self._enabled else QColor(50,50,50))
            painter.drawText(QRectF(0,0,w/2,h),Qt.AlignCenter,"RU")
            painter.setPen(QColor(100,180,255) if self._enabled else QColor(50,80,110))
            painter.drawText(QRectF(w/2,0,w/2,h),Qt.AlignCenter,"EN")
        else:
            painter.setPen(QColor(100,220,130) if self._enabled else QColor(50,100,60))
            painter.drawText(QRectF(0,0,w/2,h),Qt.AlignCenter,"RU")
            base_gray=80;hr,hg,hb=140,170,220
            r=int(base_gray+(hr-base_gray)*self._en_brightness);g=int(base_gray+(hg-base_gray)*self._en_brightness);b=int(base_gray+(hb-base_gray)*self._en_brightness)
            painter.setPen(QColor(r,g,b) if self._enabled else QColor(50,50,50))
            painter.drawText(QRectF(w/2,0,w/2,h),Qt.AlignCenter,"EN")
    def get_language(self):return "en" if self._is_english else "ru"


# ============================================================
# ЧАСТИЦЫ
# ============================================================

class ButtonGlowParticle:
    def __init__(self,x,y,color_rgb):
        self.x,self.y=float(x),float(y);self.r,self.g,self.b=color_rgb
        angle=random.uniform(0,math.pi*2);speed=random.uniform(0.2,0.4)
        self.vx,self.vy=math.cos(angle)*speed,math.sin(angle)*speed
        self.life,self.max_life=0.0,1.0;self.fade_in,self.fade_speed=True,0.02
        self.decay=random.uniform(0.004,0.008);self.size=random.uniform(2,3.5)
    def update(self):
        self.x+=self.vx;self.y+=self.vy
        if self.fade_in:
            self.life+=self.fade_speed
            if self.life>=self.max_life:self.life,self.fade_in=self.max_life,False
        else:self.life-=self.decay
        return self.life>0

class AmbientGlowParticle:
    def __init__(self,width,height,initial=True):
        self.width,self.height=width,height;self.reset(initial)
    def reset(self,initial=False):
        gray=random.randint(110,170);self.r,self.g,self.b=gray,gray,gray+random.randint(-10,20)
        side=random.choice(['top','bottom','left','right'])
        if side=='top':self.x,self.y=float(random.uniform(0,self.width)),-10.0
        elif side=='bottom':self.x,self.y=float(random.uniform(0,self.width)),float(self.height+10)
        elif side=='left':self.x,self.y=-10.0,float(random.uniform(0,self.height))
        else:self.x,self.y=float(self.width+10),float(random.uniform(0,self.height))
        self.spawn_delay=random.uniform(0,3.0) if initial else 0.0
        self.life,self.fade_in,self.max_life,self.fade_speed=0.0,True,1.0,0.015
        angle=random.uniform(0,math.pi*2);speed=random.uniform(0.1,0.25)
        self.vx,self.vy=math.cos(angle)*speed,math.sin(angle)*speed
        self.decay=random.uniform(0.001,0.003);self.size=random.uniform(1.5,3.0)
    def update(self,width,height):
        self.width,self.height=width,height
        if self.spawn_delay>0:self.spawn_delay-=0.032;return True
        self.x+=self.vx;self.y+=self.vy
        if self.fade_in:
            self.life+=self.fade_speed
            if self.life>=self.max_life:self.life,self.fade_in=self.max_life,False
        else:self.life-=self.decay
        margin=50
        if self.life<=0 or self.x<-margin or self.x>width+margin or self.y<-margin or self.y>height+margin:self.reset(initial=False)
        return True

class ParticleOverlay(QWidget):
    def __init__(self,parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WA_TransparentForMouseEvents);self.setAttribute(Qt.WA_TranslucentBackground)
        self.setStyleSheet("background: transparent;")
        self.ambient_particles,self.button_particles=[],[]
        self.tracked_buttons,self.version_button=[],None
        self.particle_spawn_timer=self.version_particle_timer=self._frame_skip=0
        self.animation_timer=QTimer();self.animation_timer.timeout.connect(self.update_particles);self.animation_timer.start(FPS_75)
    def showEvent(self,event):super().showEvent(event);self.init_particles()
    def resizeEvent(self,event):super().resizeEvent(event);self.init_particles()
    def init_particles(self):self.ambient_particles=[AmbientGlowParticle(self.width(),self.height(),True) for _ in range(50)];self.button_particles=[]
    def register_button(self,button):
        if button not in self.tracked_buttons:self.tracked_buttons.append(button)
    def register_version_button(self,button):self.version_button=button
    def update_particles(self):
        for p in self.ambient_particles:p.update(self.width(),self.height())
        self.button_particles=[p for p in self.button_particles if p.update()]
        self.particle_spawn_timer+=1
        if self.particle_spawn_timer>=30:self.particle_spawn_timer=0;self.spawn_button_particles()
        self.version_particle_timer+=1
        if self.version_particle_timer>=30:self.version_particle_timer=0;self.spawn_version_particles()
        self.update()
    def spawn_button_particles(self):
        for button in self.tracked_buttons:
            if button.is_hovered and button.isEnabled():
                btn_pos=button.mapToGlobal(button.rect().topLeft());overlay_pos=self.mapFromGlobal(btn_pos)
                x=overlay_pos.x()+button.width()/2+random.uniform(-15,15);y=overlay_pos.y()+button.height()/2+random.uniform(-5,5)
                self.button_particles.append(ButtonGlowParticle(x,y,button.base_color))
                if len(self.button_particles)>15:self.button_particles=self.button_particles[-15:]
    def spawn_version_particles(self):
        if self.version_button and hasattr(self.version_button,'has_update') and self.version_button.has_update:
            btn_pos=self.version_button.mapToGlobal(self.version_button.rect().topLeft());overlay_pos=self.mapFromGlobal(btn_pos)
            x=overlay_pos.x()+self.version_button.width()/2+random.uniform(-15,15);y=overlay_pos.y()+self.version_button.height()/2+random.uniform(-5,5)
            self.button_particles.append(ButtonGlowParticle(x,y,self.version_button.base_color))
            if len(self.button_particles)>15:self.button_particles=self.button_particles[-15:]
    def paintEvent(self,event):
        painter=QPainter(self);painter.setRenderHint(QPainter.Antialiasing);painter.setPen(Qt.NoPen)
        for p in self.ambient_particles+self.button_particles:
            if p.life<=0:continue
            alpha=int(255*p.life*0.5);glow_size=p.size*2.5
            painter.setBrush(QColor(p.r,p.g,p.b,int(alpha*0.3)))
            painter.drawEllipse(QRectF(p.x-glow_size/2,p.y-glow_size/2,glow_size,glow_size))
            painter.setBrush(QColor(p.r,p.g,p.b,alpha))
            painter.drawEllipse(QRectF(p.x-p.size/2,p.y-p.size/2,p.size,p.size))


# ============================================================
# КОНСОЛЬНЫЕ ВИДЖЕТЫ
# ============================================================

class ConsoleSpinner(QWidget):
    def __init__(self,color="#64DC82",size=16,parent=None):
        super().__init__(parent);self.setFixedSize(size,size)
        self.color,self.angle,self._is_stopped=QColor(color),0,False
        self.timer=QTimer();self.timer.timeout.connect(self.rotate);self.timer.start(FPS_75)
    def rotate(self):
        if not self._is_stopped:self.angle=(self.angle+6)%360;self.update()
    def set_color(self,color):self.color=QColor(color)
    def paintEvent(self,event):
        if self._is_stopped:return
        painter=QPainter(self);painter.setRenderHint(QPainter.Antialiasing)
        size=min(self.width(),self.height());center,radius=size/2,size/2-2
        painter.setPen(QPen(QColor(self.color.red(),self.color.green(),self.color.blue(),50),2))
        painter.drawEllipse(QRectF(2,2,size-4,size-4))
        painter.setPen(QPen(self.color,2,Qt.SolidLine,Qt.RoundCap))
        painter.translate(center,center);painter.rotate(self.angle)
        painter.drawArc(QRectF(-radius,-radius,radius*2,radius*2),0,90*16)
    def stop(self):self._is_stopped=True;self.timer.stop()

class ConsoleDots(QWidget):
    def __init__(self,color="#64DC82",parent=None):
        super().__init__(parent);self.setFixedSize(36,16)
        self.color,self.phase,self._is_stopped=QColor(color),0.0,False
        self.timer=QTimer();self.timer.timeout.connect(self.animate);self.timer.start(FPS_75)
    def set_color(self,color):self.color=QColor(color)
    def animate(self):
        if not self._is_stopped:self.phase=(self.phase+0.12)%4.0;self.update()
    def paintEvent(self,event):
        if self._is_stopped:return
        painter=QPainter(self);painter.setRenderHint(QPainter.Antialiasing)
        for i in range(3):
            alpha=max(60,int(255*max(0,1-abs(self.phase-i-0.5)*0.6)))
            painter.setBrush(QColor(self.color.red(),self.color.green(),self.color.blue(),alpha))
            painter.setPen(Qt.NoPen);painter.drawEllipse(i*12+2,4,8,8)
    def stop(self):self._is_stopped=True;self.timer.stop()

class ConsoleWave(QWidget):
    def __init__(self,color="#64DC82",parent=None):
        super().__init__(parent);self.setFixedSize(44,18)
        self.color=QColor(color);self.heights=[0.3,0.5,0.7,0.5,0.3]
        self.targets=[random.uniform(0.3,1.0) for _ in range(5)];self._is_stopped=False
        self.timer=QTimer();self.timer.timeout.connect(self.animate);self.timer.start(FPS_75)
    def set_color(self,color):self.color=QColor(color)
    def animate(self):
        if self._is_stopped:return
        for i in range(5):
            diff=self.targets[i]-self.heights[i];self.heights[i]+=diff*0.12
            if abs(diff)<0.05:self.targets[i]=random.uniform(0.3,1.0)
        self.update()
    def paintEvent(self,event):
        if self._is_stopped:return
        painter=QPainter(self);painter.setRenderHint(QPainter.Antialiasing)
        for i,h in enumerate(self.heights):
            height=int(16*h);x,y=i*9,16-height
            gradient=QLinearGradient(x,y,x,16)
            gradient.setColorAt(0,self.color);gradient.setColorAt(1,QColor(self.color.red(),self.color.green(),self.color.blue(),120))
            painter.setBrush(gradient);painter.setPen(Qt.NoPen);painter.drawRoundedRect(x,y,5,height,2,2)
    def stop(self):self._is_stopped=True;self.timer.stop()

class ConsolePulse(QWidget):
    def __init__(self,color="#64DC82",parent=None):
        super().__init__(parent);self.setFixedSize(18,18)
        self.color,self.scale,self.growing,self._is_stopped=QColor(color),0.5,True,False
        self.timer=QTimer();self.timer.timeout.connect(self.animate);self.timer.start(FPS_75)
    def set_color(self,color):self.color=QColor(color)
    def animate(self):
        if self._is_stopped:return
        if self.growing:
            self.scale+=0.012
            if self.scale>=1.0:self.growing=False
        else:
            self.scale-=0.012
            if self.scale<=0.5:self.growing=True
        self.update()
    def paintEvent(self,event):
        if self._is_stopped:return
        painter=QPainter(self);painter.setRenderHint(QPainter.Antialiasing)
        center,max_r=self.width()/2,self.width()/2-2;radius=max_r*self.scale
        painter.setPen(QPen(QColor(self.color.red(),self.color.green(),self.color.blue(),int(255*(1-self.scale)*0.8)),2))
        painter.drawEllipse(QPointF(center,center),radius,radius)
        painter.setBrush(self.color);painter.setPen(Qt.NoPen)
        painter.drawEllipse(QPointF(center,center),3,3)
    def stop(self):self._is_stopped=True;self.timer.stop()

class ConsoleCubeGrid(QWidget):
    def __init__(self,color="#FFB432",parent=None):
        super().__init__(parent);self.setFixedSize(20,20)
        self.color,self._is_stopped,self.time=QColor(color),False,0.0
        self.delays=[0.2,0.3,0.4,0.1,0.2,0.3,0.0,0.1,0.2]
        self.timer=QTimer();self.timer.timeout.connect(self.animate);self.timer.start(FPS_75)
    def set_color(self,color):self.color=QColor(color)
    def animate(self):
        if self._is_stopped:return
        self.time=(self.time+0.016)%1.3;self.update()
    def paintEvent(self,event):
        if self._is_stopped:return
        painter=QPainter(self);painter.setRenderHint(QPainter.Antialiasing);painter.setPen(Qt.NoPen)
        cube_size=self.width()/3.0
        for i in range(9):
            t=(self.time-self.delays[i])%1.3;p=t/1.3
            scale=1.0-p/0.35 if p<0.35 else (p-0.35)/0.35 if p<0.70 else 1.0
            scale=max(0,min(1,scale*scale*(3-2*scale)));size=(cube_size-1)*scale
            if size>0.5:
                cx,cy=(i%3)*cube_size+cube_size/2,(i//3)*cube_size+cube_size/2
                painter.setBrush(QColor(self.color.red(),self.color.green(),self.color.blue(),int(180+75*scale)))
                painter.drawRoundedRect(QRectF(cx-size/2,cy-size/2,size,size),1,1)
    def stop(self):self._is_stopped=True;self.timer.stop()

class ShimmerTextLabel(QWidget):
    _global_shimmer_pos=-0.3;_global_timer=None;_instances=[]
    @classmethod
    def _start_global_timer(cls):
        if cls._global_timer is None:
            cls._global_timer=QTimer();cls._global_timer.timeout.connect(cls._global_animate);cls._global_timer.start(FPS_75)
    @classmethod
    def _global_animate(cls):
        cls._global_shimmer_pos+=0.015
        if cls._global_shimmer_pos>1.3:cls._global_shimmer_pos=-0.3
        for inst in cls._instances:
            if inst._is_active:inst.update()
    def __init__(self,text,color="#888888",icon="›",parent=None):
        super().__init__(parent)
        self._text,self._icon,self._base_color=text,icon,QColor(color)
        self._is_active,self._opacity=True,1.0
        self.setMinimumHeight(18);self.setSizePolicy(QSizePolicy.Expanding,QSizePolicy.Preferred)
        ShimmerTextLabel._instances.append(self);ShimmerTextLabel._start_global_timer()
    def setText(self,text):self._text=text;self.update()
    def setOpacity(self,opacity):self._opacity=opacity;self.update()
    def paintEvent(self,event):
        painter=QPainter(self);painter.setRenderHint(QPainter.TextAntialiasing)
        base=self._base_color;alpha=int(255*self._opacity)
        if self._is_active:
            gradient=QLinearGradient(0,0,self.width(),0)
            bright=QColor(min(255,base.red()+100),min(255,base.green()+100),min(255,base.blue()+100),alpha)
            base_a=QColor(base.red(),base.green(),base.blue(),alpha)
            p,w=ShimmerTextLabel._global_shimmer_pos,0.15
            gradient.setColorAt(0,base_a);gradient.setColorAt(max(0,min(1,p-w)),base_a)
            gradient.setColorAt(max(0,min(1,p)),bright);gradient.setColorAt(max(0,min(1,p+w)),base_a);gradient.setColorAt(1,base_a)
            pen=QPen();pen.setBrush(QBrush(gradient));painter.setPen(pen)
        else:painter.setPen(QColor(base.red(),base.green(),base.blue(),alpha))
        font=QFont("Cascadia Code",9)
        if not QFont("Cascadia Code").exactMatch():font=QFont("Consolas",9)
        painter.setFont(font);painter.drawText(self.rect().adjusted(4,0,0,0),Qt.AlignLeft|Qt.AlignVCenter,f"{self._icon}  {self._text}")
    def stop(self):self._is_active=False;self.update()
    def __del__(self):
        try:ShimmerTextLabel._instances.remove(self)
        except:pass

class ConsoleMessage(QFrame):
    def __init__(self,text,msg_type="default",parent=None):
        super().__init__(parent);self.msg_type=msg_type
        self.type_config={
            "success":{"icon":"●","color":"#64DC82"},"error":{"icon":"●","color":"#FF5050"},
            "warning":{"icon":"●","color":"#FFB432"},"info":{"icon":"●","color":"#22D3EE"},
            "default":{"icon":"›","color":"#888888"},"cyan":{"icon":"●","color":"#22D3EE"},
            "gray":{"icon":"›","color":"#888888"},"orange":{"icon":"●","color":"#E67850"},
            "red":{"icon":"●","color":"#FF5050"},"green":{"icon":"●","color":"#64DC82"},
            "yellow":{"icon":"●","color":"#FFB432"},"white":{"icon":"●","color":"#E0E0E0"},
        }
        config=self.type_config.get(msg_type,self.type_config["default"])
        self._config,self._opacity,self._hover_glow,self._target_glow=config,0.0,0.0,0.0
        color=config['color']
        self._color_r,self._color_g,self._color_b=int(color[1:3],16),int(color[3:5],16),int(color[5:7],16)
        self._use_shimmer=msg_type=="gray";self._update_style()
        layout=QHBoxLayout();layout.setContentsMargins(8,4,8,4);layout.setSpacing(8)
        if self._use_shimmer:
            self._icon_label=None;self._text_label=ShimmerTextLabel(text,config['color'],"›");self._text_label.setOpacity(0.0)
        else:
            self._icon_label=QLabel(config['icon']);self._icon_label.setFixedWidth(20);self._icon_label.setAlignment(Qt.AlignCenter)
            self._text_label=QLabel(text);self._text_label.setWordWrap(True)
        self._update_labels()
        if self._icon_label:layout.addWidget(self._icon_label)
        layout.addWidget(self._text_label,1);self.setLayout(layout)
        self._fade_timer=QTimer();self._fade_timer.timeout.connect(self._animate_fade);self._fade_timer.start(FPS_75)
        self._hover_timer=QTimer();self._hover_timer.timeout.connect(self._animate_hover);self._hover_timer.start(FPS_75)
    def enterEvent(self,e):self._target_glow=1.0
    def leaveEvent(self,e):self._target_glow=0.0
    def _animate_hover(self):
        diff=self._target_glow-self._hover_glow
        if abs(diff)>0.01:
            self._hover_glow=min(1.0,max(0.0,self._hover_glow+diff*0.15))
            self._update_style();self._update_labels()
    def _animate_fade(self):
        self._opacity=min(1.0,self._opacity+0.06)
        self._update_style();self._update_labels()
        if self._opacity>=1.0:self._fade_timer.stop()
    def _update_style(self):
        r,g,b=self._color_r,self._color_g,self._color_b
        bg_a=(0.08+0.12*self._hover_glow)*self._opacity
        self.setStyleSheet(f"QFrame{{background:rgba({r},{g},{b},{bg_a});border-left:3px solid rgba({r},{g},{b},{self._opacity});border-radius:4px;margin:1px 2px 1px 0px;}}")
    def _update_labels(self):
        r,g,b=self._color_r,self._color_g,self._color_b
        boost=1.0+0.2*self._hover_glow
        rb,gb,bb=min(255,int(r*boost)),min(255,int(g*boost)),min(255,int(b*boost));alpha=int(255*self._opacity)
        if self._use_shimmer:self._text_label.setOpacity(self._opacity)
        else:
            self._icon_label.setStyleSheet(f"color:rgba({rb},{gb},{bb},{alpha});font-size:14px;background:transparent;border:none;")
            self._text_label.setStyleSheet(f"color:rgba({rb},{gb},{bb},{alpha});font-size:12px;font-weight:500;font-family:'Cascadia Code','Consolas',monospace;background:transparent;border:none;")

class ConsoleHeader(QFrame):
    def __init__(self,text,color="#64DC82",icon=None,parent=None):
        super().__init__(parent);self.color=color
        self._opacity,self._hover_glow,self._target_glow=0.0,0.0,0.0
        c=color.lstrip('#');self._color_r,self._color_g,self._color_b=int(c[0:2],16),int(c[2:4],16),int(c[4:6],16)
        self._update_style()
        layout=QHBoxLayout();layout.setContentsMargins(12,8,12,8)
        self._text_label=QLabel(text);self._text_label.setAlignment(Qt.AlignCenter);self._update_label()
        layout.addStretch();layout.addWidget(self._text_label);layout.addStretch()
        self.setLayout(layout)
        self._fade_timer=QTimer();self._fade_timer.timeout.connect(self._animate_fade);self._fade_timer.start(FPS_75)
        self._hover_timer=QTimer();self._hover_timer.timeout.connect(self._animate_hover);self._hover_timer.start(FPS_75)
    def enterEvent(self,e):self._target_glow=1.0
    def leaveEvent(self,e):self._target_glow=0.0
    def _animate_hover(self):
        diff=self._target_glow-self._hover_glow
        if abs(diff)>0.01:
            self._hover_glow=min(1.0,max(0.0,self._hover_glow+diff*0.15))
            self._update_style();self._update_label()
    def _animate_fade(self):
        self._opacity=min(1.0,self._opacity+0.05)
        self._update_style();self._update_label()
        if self._opacity>=1.0:self._fade_timer.stop()
    def _update_style(self):
        r,g,b=self._color_r,self._color_g,self._color_b
        bg1=(0.15+0.15*self._hover_glow)*self._opacity;bg2=(0.05+0.1*self._hover_glow)*self._opacity
        self.setStyleSheet(f"QFrame{{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 rgba({r},{g},{b},{bg1}),stop:1 rgba({r},{g},{b},{bg2}));border:1.5px solid rgba({r},{g},{b},{self._opacity});border-radius:8px;margin:4px 2px 4px 0px;}}")
    def _update_label(self):
        r,g,b=self._color_r,self._color_g,self._color_b
        boost=1.0+0.2*self._hover_glow;rb,gb,bb=min(255,int(r*boost)),min(255,int(g*boost)),min(255,int(b*boost))
        self._text_label.setStyleSheet(f"color:rgba({rb},{gb},{bb},{int(255*self._opacity)});font-size:12px;font-weight:bold;background:transparent;border:none;")

class ConsoleLoadingMessage(QFrame):
    def __init__(self,text,loading_type="spinner",color="#64DC82",parent=None):
        super().__init__(parent);self.color,self._opacity,self._is_stopped=color,0.0,False
        self._update_style()
        layout=QHBoxLayout();layout.setContentsMargins(10,6,10,6);layout.setSpacing(10)
        loaders={"spinner":ConsoleSpinner,"dots":ConsoleDots,"wave":ConsoleWave,"pulse":ConsolePulse,"cubes":ConsoleCubeGrid}
        self.loader=loaders.get(loading_type,ConsoleSpinner)(color);layout.addWidget(self.loader)
        self.text_label=QLabel(text);self._update_label();layout.addWidget(self.text_label,1);self.setLayout(layout)
        self._fade_timer=QTimer();self._fade_timer.timeout.connect(self._animate_fade);self._fade_timer.start(FPS_75)
    def _hex_rgb(self,c):c=c.lstrip('#');return int(c[0:2],16),int(c[2:4],16),int(c[4:6],16)
    def _update_style(self):
        r,g,b=self._hex_rgb(self.color)
        self.setStyleSheet(f"QFrame{{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 rgba({r},{g},{b},{0.1*self._opacity}),stop:1 rgba({r},{g},{b},{0.03*self._opacity}));border:1px solid rgba({r},{g},{b},{0.3*self._opacity});border-radius:6px;margin:2px;}}")
    def _update_label(self):
        r,g,b=self._hex_rgb(self.color)
        self.text_label.setStyleSheet(f"color:rgba({r},{g},{b},{int(255*self._opacity)});font-size:12px;font-weight:500;font-family:'Cascadia Code','Consolas',monospace;background:transparent;border:none;")
    def _animate_fade(self):
        if self._is_stopped:return
        self._opacity=min(1.0,self._opacity+0.08);self._update_style();self._update_label()
        if self._opacity>=1.0:self._fade_timer.stop()
    def set_text(self,text):self.text_label.setText(text)
    def stop(self):self._is_stopped=True;self._fade_timer.stop();self.loader.stop()
    def remove_animated(self):self.stop();self.deleteLater()

class ModernConsole(QFrame):
    message_added=Signal()
    def __init__(self,parent=None):
        super().__init__(parent)
        self.messages,self.current_loading,self.message_queue=[],None,[]
        self.queue_timer=QTimer();self.queue_timer.setSingleShot(True);self.queue_timer.timeout.connect(self._process_queue)
        self.last_message_time=self.last_add_time=0
        self.DELAY_SAME_BATCH,self.DELAY_NEW_BATCH,self.BATCH_TIMEOUT=80,400,150
        self._scroll_target=0;self._scroll_current=0.0
        self._scroll_timer=QTimer();self._scroll_timer.timeout.connect(self._animate_scroll);self._scroll_timer.start(FPS_75)
        self.setup_ui()
    def setup_ui(self):
        self.setObjectName("console_main")
        self.setStyleSheet("QFrame#console_main{background:qlineargradient(x1:0,y1:0,x2:0,y2:1,stop:0 rgba(10,10,12,0.98),stop:1 rgba(15,15,18,0.98));border:2px solid rgba(100,220,130,0.4);border-radius:10px;}")
        main_layout=QVBoxLayout();main_layout.setContentsMargins(0,0,0,0)
        self.scroll_area=QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOn)
        self.scroll_area.setStyleSheet("QScrollArea{background:transparent;border:none;}QScrollBar:vertical{background:transparent;width:4px;margin:6px 2px 6px 0px;border:none;}QScrollBar::handle:vertical{background:rgba(100,220,130,0.15);border-radius:2px;min-height:20px;}QScrollBar::handle:vertical:hover{background:rgba(100,220,130,0.3);}QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{height:0px;border:none;}QScrollBar::add-page:vertical,QScrollBar::sub-page:vertical{background:transparent;}")
        self.messages_container=QWidget();self.messages_container.setStyleSheet("background:transparent;")
        self.messages_layout=QVBoxLayout();self.messages_layout.setContentsMargins(8,8,8,8);self.messages_layout.setSpacing(2)
        self.messages_layout.addStretch();self.messages_container.setLayout(self.messages_layout)
        self.scroll_area.setWidget(self.messages_container)
        main_layout.addWidget(self.scroll_area,1);self.setLayout(main_layout)
        self.message_added.connect(self.scroll_to_bottom)
    def _process_queue(self):
        if not self.message_queue:return
        msg=self.message_queue.pop(0)
        if msg['type']=='message':self._add_message_immediate(msg['text'],msg['msg_type'])
        elif msg['type']=='header':self._add_header_immediate(msg['text'],msg['color'],msg['icon'])
        self.last_message_time=time.time()*1000
        if self.message_queue:
            delay=self.DELAY_NEW_BATCH if self.message_queue[0].get('is_new_batch') else self.DELAY_SAME_BATCH
            self.queue_timer.start(delay)
    def _add_to_queue(self,msg):
        current=time.time()*1000
        is_new=(current-self.last_add_time>self.BATCH_TIMEOUT) or msg.get('type')=='header'
        msg['is_new_batch']=is_new;self.last_add_time=current
        self.message_queue.append(msg)
        if self.queue_timer.isActive():return
        delay=self.DELAY_NEW_BATCH if is_new else self.DELAY_SAME_BATCH
        elapsed=current-self.last_message_time
        if elapsed>=delay:self._process_queue()
        else:self.queue_timer.start(int(delay-elapsed))
    def _stop_all_shimmers(self):
        for m in self.messages:
            if isinstance(m,ConsoleMessage) and m.msg_type=="gray" and hasattr(m,'_text_label') and isinstance(m._text_label,ShimmerTextLabel):m._text_label.stop()
    def _add_message_immediate(self,text,msg_type="default"):
        if msg_type!="gray" and self.current_loading is None:self._stop_all_shimmers()
        msg=ConsoleMessage(text,msg_type);self.messages_layout.insertWidget(self.messages_layout.count()-1,msg)
        self.messages.append(msg);self._cleanup();self.message_added.emit()
    def _add_header_immediate(self,text,color="#64DC82",icon=""):
        if self.current_loading is None:self._stop_all_shimmers()
        header=ConsoleHeader(text,color,icon);self.messages_layout.insertWidget(self.messages_layout.count()-1,header)
        self.messages.append(header);self._cleanup();self.message_added.emit()
    def add_message(self,text,msg_type="default"):self._add_to_queue({'type':'message','text':text,'msg_type':msg_type})
    def add_header(self,text,color="#64DC82",icon=""):self._add_to_queue({'type':'header','text':text,'color':color,'icon':icon})
    def _cleanup(self):pass
    def show_loading(self,text,loading_type="spinner",color="#64DC82"):
        self.hide_loading();self.current_loading=ConsoleLoadingMessage(text,loading_type,color)
        self.messages_layout.insertWidget(self.messages_layout.count()-1,self.current_loading);self.message_added.emit()
        return self.current_loading
    def hide_loading(self):
        if self.current_loading:self.current_loading.remove_animated();self.current_loading=None;self._stop_all_shimmers()
    def update_loading_text(self,text):
        if self.current_loading:self.current_loading.set_text(text)
    def clear(self):
        self.message_queue=[];self.queue_timer.stop();self.last_message_time=self.last_add_time=0
        while self.messages_layout.count()>1:
            item=self.messages_layout.takeAt(0)
            if item.widget():item.widget().deleteLater()
        self.messages,self.current_loading=[],None
    def scroll_to_bottom(self):QTimer.singleShot(10,self._instant_scroll)
    def _instant_scroll(self):self.scroll_area.verticalScrollBar().setValue(self.scroll_area.verticalScrollBar().maximum())
    def _animate_scroll(self):pass


# ============================================================
# ОСТАЛЬНЫЕ КОМПОНЕНТЫ
# ============================================================

class AnimatedProgressBar(QWidget):
    def __init__(self,color="#B478FF",parent=None):
        super().__init__(parent);self.setFixedHeight(48);self.setMinimumWidth(200)
        self._progress,self._target_progress,self._shimmer_pos=0.0,0.0,0.0
        self._color=QColor(color);self._downloaded_mb,self._total_mb,self._show_size=0.0,0.0,False
        self.timer=QTimer();self.timer.timeout.connect(self._animate);self.timer.start(FPS_75)
    def set_progress(self,value):self._target_progress=max(0.0,min(100.0,value))
    def set_size(self,downloaded_mb,total_mb):self._downloaded_mb,self._total_mb,self._show_size=downloaded_mb,total_mb,True
    def _animate(self):
        diff=self._target_progress-self._progress
        self._progress=self._progress+diff*0.15 if abs(diff)>0.1 else self._target_progress
        self._shimmer_pos=(self._shimmer_pos+0.02) if self._shimmer_pos<=1.5 else -0.5;self.update()
    def paintEvent(self,event):
        painter=QPainter(self);painter.setRenderHint(QPainter.Antialiasing)
        w,h,r=self.width(),self.height(),self.height()/2
        painter.setPen(Qt.NoPen);painter.setBrush(QColor(30,30,35,200));painter.drawRoundedRect(0,0,w,h,r,r)
        painter.setPen(QPen(QColor(self._color.red(),self._color.green(),self._color.blue(),100),2))
        painter.setBrush(Qt.NoBrush);painter.drawRoundedRect(1,1,w-2,h-2,r,r)
        if self._progress>0:
            pw=int((w-4)*self._progress/100)
            if pw>0:
                grad=QLinearGradient(2,0,2+pw,0)
                grad.setColorAt(0,QColor(self._color.red(),self._color.green(),self._color.blue(),200));grad.setColorAt(1,self._color)
                painter.setPen(Qt.NoPen);painter.setBrush(grad);painter.drawRoundedRect(2,2,pw,h-4,r-2,r-2)
                shimmer_x=int(pw*self._shimmer_pos)
                if 0<shimmer_x<pw:
                    shimmer_grad=QLinearGradient(shimmer_x-20,0,shimmer_x+20,0)
                    shimmer_grad.setColorAt(0,QColor(255,255,255,0));shimmer_grad.setColorAt(0.5,QColor(255,255,255,60));shimmer_grad.setColorAt(1,QColor(255,255,255,0))
                    painter.setBrush(shimmer_grad);painter.drawRoundedRect(2,2,pw,h-4,r-2,r-2)
        painter.setPen(QColor(255,255,255,230));painter.setFont(QFont("Segoe UI",10,QFont.Bold))
        painter.drawText(QRectF(0,4,w,h/2-2),Qt.AlignCenter,f"{int(self._progress)}%")
        if self._show_size and self._total_mb>0:
            mb=get_text("size_mb");painter.setPen(QColor(255,255,255,180));painter.setFont(QFont("Segoe UI",8))
            painter.drawText(QRectF(0,h/2,w,h/2-4),Qt.AlignCenter,f"{self._downloaded_mb:.1f} {mb} / {self._total_mb:.1f} {mb}")
    def stop(self):self.timer.stop()

class ConfirmDialogButton(QPushButton):
    def __init__(self,text,color,parent=None):
        super().__init__(text,parent);self.base_color=color
        self.text_brightness=self.border_brightness=0;self.is_hovered=False
        self.setFixedHeight(40);self.setCursor(Qt.PointingHandCursor);self.update_style()
        self.hover_timer=QTimer();self.hover_timer.timeout.connect(self.animate_hover);self.hover_timer.start(HOVER_SPEED)
    def enterEvent(self,event):self.is_hovered=True;super().enterEvent(event)
    def leaveEvent(self,event):self.is_hovered=False;super().leaveEvent(event)
    def update_style(self):
        r,g,b=self.base_color;tb,bdb=self.text_brightness,self.border_brightness
        clamp=lambda v:max(0,min(255,int(v)))
        tr,tg,tb_c=clamp(r*0.6+tb),clamp(g*0.6+tb),clamp(b*0.6+tb)
        br,bg_val,bb=clamp(r*0.5+bdb),clamp(g*0.5+bdb),clamp(b*0.5+bdb);ba=0.3+(bdb/100)
        self.setStyleSheet(f"""QPushButton {{background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 rgba(25,25,30,0.8), stop:1 rgba(20,20,25,0.8));color: rgba({tr},{tg},{tb_c},255); border: 1.5px solid rgba({br},{bg_val},{bb},{ba}); border-radius: 10px;padding: 8px 20px; font-weight: bold; font-size: 12px;}}QPushButton:pressed {{background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 rgba(15,15,20,0.8), stop:1 rgba(20,20,25,0.8));padding-top: 10px; padding-bottom: 6px;}}""")
    def animate_hover(self):
        if self.is_hovered:self.text_brightness=min(60,self.text_brightness+4);self.border_brightness=min(60,self.border_brightness+4)
        else:self.text_brightness=max(0,self.text_brightness-4);self.border_brightness=max(0,self.border_brightness-4)
        self.update_style()

class VersionButton(QPushButton):
    clicked_for_update=Signal()
    def __init__(self,text,parent=None):
        super().__init__(text,parent);self.base_color=(180,120,255)
        self.text_brightness=self.border_brightness=0;self.is_hovered=False
        self.has_update=False;self.cached_update_info=None
        self.setFixedHeight(28);self.setMinimumWidth(60);self.setCursor(Qt.PointingHandCursor);self.update_style()
        self.hover_timer=QTimer();self.hover_timer.timeout.connect(self.animate_hover);self.hover_timer.start(HOVER_SPEED)
    def set_update_available(self,available,update_info=None):self.has_update=available;self.cached_update_info=update_info;self.update_style()
    def enterEvent(self,event):self.is_hovered=True;super().enterEvent(event)
    def leaveEvent(self,event):self.is_hovered=False;super().leaveEvent(event)
    def update_style(self):
        r,g,b=self.base_color;tb,bdb=self.text_brightness,self.border_brightness
        clamp=lambda v:max(0,min(255,int(v)))
        tr,tg,tb_c=clamp(r*0.6+tb),clamp(g*0.6+tb),clamp(b*0.6+tb)
        br,bg_val,bb=clamp(r*0.5+bdb),clamp(g*0.5+bdb),clamp(b*0.5+bdb)
        ba=0.4+(bdb/100) if self.has_update else 0.3+(bdb/100)
        self.setStyleSheet(f"""QPushButton {{background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 rgba(25,25,30,0.95), stop:1 rgba(20,20,25,0.95));color: rgba({tr},{tg},{tb_c},255); border: 1.5px solid rgba({br},{bg_val},{bb},{ba}); border-radius: 8px;padding: 4px 12px; font-weight: bold; font-size: 10px;}}QPushButton:pressed {{background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 rgba(15,15,20,0.95), stop:1 rgba(20,20,25,0.95));padding-top: 5px; padding-bottom: 3px;}}""")
    def animate_hover(self):
        if self.is_hovered:self.text_brightness=min(60,self.text_brightness+4);self.border_brightness=min(60,self.border_brightness+4)
        else:self.text_brightness=max(0,self.text_brightness-4);self.border_brightness=max(0,self.border_brightness-4)
        self.update_style()

class LinkLabel(QLabel):
    def __init__(self,text,parent=None):
        super().__init__(text,parent);self.link_brightness=0;self.is_link_hovered=False
        self.setOpenExternalLinks(True);self.setAlignment(Qt.AlignLeft);self.setFont(QFont("Segoe UI",8))
        self.link_timer=QTimer();self.link_timer.timeout.connect(self.animate_link);self.link_timer.start(HOVER_SPEED)
        self.update_link_style()
    def update_link_style(self):
        base_r,base_g,base_b=100,220,130
        cr=min(255,int(base_r*0.6+self.link_brightness));cg=min(255,int(base_g*0.6+self.link_brightness));cb=min(255,int(base_b*0.6+self.link_brightness))
        link_color=f"rgb({cr}, {cg}, {cb})";self.setStyleSheet("color: #888888; margin-top: 1px;")
        self.setText(f'{get_text("footer_unofficial")}<a href="https://spicetify.app" style="color: {link_color}; text-decoration: none;">spicetify.app</a>')
    def animate_link(self):
        if self.is_link_hovered:self.link_brightness=min(60,self.link_brightness+4)
        else:self.link_brightness=max(0,self.link_brightness-4)
        self.update_link_style()
    def mouseMoveEvent(self,event):
        plain=get_text("footer_unofficial")
        if event.position().toPoint().x()>self.fontMetrics().horizontalAdvance(plain):self.is_link_hovered=True;self.setCursor(Qt.PointingHandCursor)
        else:self.is_link_hovered=False;self.setCursor(Qt.ArrowCursor)
    def leaveEvent(self,event):self.is_link_hovered=False;self.setCursor(Qt.ArrowCursor)

class GlowButton(QPushButton):
    def __init__(self,text,color,parent=None):
        super().__init__(text,parent);self.base_color=color
        self.text_brightness=0;self.border_brightness=0;self.is_hovered=False;self._is_disabled=False
        self.setFixedHeight(55);self.setCursor(Qt.PointingHandCursor);self.update_style()
        self.hover_timer=QTimer();self.hover_timer.timeout.connect(self.animate_hover);self.hover_timer.start(HOVER_SPEED)
    def setEnabled(self,enabled):
        super().setEnabled(enabled);self._is_disabled=not enabled
        if not enabled:self.setCursor(Qt.ForbiddenCursor);self.is_hovered=False;self.text_brightness=0;self.border_brightness=0
        else:self.setCursor(Qt.PointingHandCursor)
        self.update_style()
    def enterEvent(self,event):
        if not self._is_disabled:self.is_hovered=True
        super().enterEvent(event)
    def leaveEvent(self,event):self.is_hovered=False;super().leaveEvent(event)
    def update_style(self):
        r,g,b=self.base_color;tb,bdb=self.text_brightness,self.border_brightness
        clamp=lambda v:max(0,min(255,int(v)))
        if r>200 and g<100 and b<100:tr,tg,tb_c=clamp(r*0.55+tb),clamp(g*0.55+tb),clamp(b*0.55+tb);br,bg,bb=clamp(r*0.45+bdb),clamp(g*0.45+bdb),clamp(b*0.45+bdb);ba=0.3+(bdb/100)
        elif g>180 and r<150 and b<180:tr,tg,tb_c=clamp(r*0.6+tb),clamp(g*0.6+tb),clamp(b*0.6+tb);br,bg,bb=clamp(r*0.5+bdb),clamp(g*0.5+bdb),clamp(b*0.5+bdb);ba=0.3+(bdb/100)
        elif r>200 and g>100 and g<150 and b<100:tr,tg,tb_c=clamp(r*0.65+tb),clamp(g*0.65+tb),clamp(b*0.65+tb);br,bg,bb=clamp(r*0.55+bdb),clamp(g*0.55+bdb),clamp(b*0.55+bdb);ba=0.35+(bdb/100)
        else:tr,tg,tb_c=clamp(r*0.6+tb),clamp(g*0.6+tb),clamp(b*0.6+tb);br,bg,bb=clamp(r*0.5+bdb),clamp(g*0.5+bdb),clamp(b*0.5+bdb);ba=0.3+(bdb/100)
        self.setStyleSheet(f"""QPushButton {{background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 rgba(25,25,30,0.95), stop:1 rgba(20,20,25,0.95));color: rgba({tr},{tg},{tb_c},255); border: 1.5px solid rgba({br},{bg},{bb},{ba}); border-radius: 12px;padding: 12px 20px; font-weight: bold; font-size: 13px;}}QPushButton:pressed {{background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 rgba(15,15,20,0.95), stop:1 rgba(20,20,25,0.95));padding-top: 14px; padding-bottom: 10px;}}QPushButton:disabled {{background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 rgba(20,20,25,0.95), stop:1 rgba(15,15,20,0.95));color: rgba({clamp(r*0.4)},{clamp(g*0.4)},{clamp(b*0.4)},255); border: 1.5px solid rgba({clamp(r*0.3)},{clamp(g*0.3)},{clamp(b*0.3)},0.3);}}""")
    def animate_hover(self):
        if self.is_hovered and not self._is_disabled:self.text_brightness=min(60,self.text_brightness+4);self.border_brightness=min(60,self.border_brightness+4)
        else:self.text_brightness=max(0,self.text_brightness-4);self.border_brightness=max(0,self.border_brightness-4)
        self.update_style()

class FlameIcon(QLabel):
    def __init__(self,icon_path=None,parent=None):
        super().__init__(parent);self.setFixedSize(32,32)
        try:
            pixmap=QPixmap(":/assets/spicetify.png")
            if not pixmap.isNull():self.setPixmap(pixmap.scaled(self.size(),Qt.KeepAspectRatio,Qt.SmoothTransformation));self.setAlignment(Qt.AlignCenter)
        except:pass


# ============================================================
# ИНДИКАТОР ОБНОВЛЕНИЙ
# ============================================================

class UpdateIndicator(QWidget):
    def __init__(self,parent=None):
        super().__init__(parent);self.setFixedSize(28,28)
        self.opacity=1.0;self.status_type="checking";self.pulse_direction=-1
        self.timer=QTimer();self.timer.timeout.connect(self.animate_pulse);self.timer.start(FPS_75)
    def set_status(self,status_type):self.status_type=status_type;self.update()
    def animate_pulse(self):
        self.opacity+=self.pulse_direction*0.015
        if self.opacity<=0.4:self.pulse_direction=1
        elif self.opacity>=1.0:self.pulse_direction=-1
        self.update()
    def paintEvent(self,event):
        painter=QPainter(self);painter.setRenderHint(QPainter.Antialiasing)
        colors={"not_installed":(255,80,80),"update_available":(255,180,50)}
        r,g,b=colors.get(self.status_type,(100,220,130))
        color=QColor(r,g,b,int(255*self.opacity))
        for i in range(4):
            size=12+i*3;glow=QColor(r,g,b,int(120*self.opacity*(1-i*0.25)))
            painter.setPen(Qt.NoPen);painter.setBrush(glow)
            painter.drawRoundedRect(int((self.width()-size)/2),int((self.height()-size)/2),size,size,4,4)
        painter.setBrush(color);painter.drawRoundedRect(int((self.width()-10)/2),int((self.height()-10)/2),10,10,3,3)


# ============================================================
# ДИАЛОГИ
# ============================================================

class ConfirmDialog(QDialog):
    def __init__(self,message,title_text,border_color="green",parent=None):
        super().__init__(parent);self.setWindowFlags(Qt.FramelessWindowHint|Qt.Dialog)
        self.setAttribute(Qt.WA_TranslucentBackground);self.setModal(True)
        self.confirmed=False;self.border_color=border_color
        colors={"red":("#FF5050","255,80,80"),"orange":("#E67850","230,120,80"),"yellow":("#FFB432","255,180,50")}
        self.icon_color,self.color_rgb=colors.get(border_color,("#64DC82","100,220,130"))
        main_layout=QVBoxLayout();main_layout.setContentsMargins(0,0,0,0)
        self.container=QFrame()
        self.container.setStyleSheet(f"QFrame{{background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 rgba(18,18,22,0.96),stop:1 rgba(16,16,20,0.96));border:2px solid rgba({self.color_rgb},0.6);border-radius:16px;}}")
        cl=QVBoxLayout();cl.setContentsMargins(30,25,30,25);cl.setSpacing(20)
        icon=QLabel("?");icon.setAlignment(Qt.AlignCenter)
        icon.setStyleSheet(f"QLabel{{color:{self.icon_color};font-size:32px;font-weight:bold;background:rgba({self.color_rgb},0.15);border:2px solid rgba({self.color_rgb},0.4);border-radius:25px;min-width:50px;max-width:50px;min-height:50px;max-height:50px;}}")
        ic=QHBoxLayout();ic.addStretch();ic.addWidget(icon);ic.addStretch()
        title=QLabel(title_text);title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet(f"QLabel{{color:{self.icon_color};font-size:16px;font-weight:bold;background:transparent;border:none;}}")
        msg=QLabel(message);msg.setAlignment(Qt.AlignCenter);msg.setWordWrap(True)
        msg.setStyleSheet("QLabel{color:#E0E0E0;font-size:13px;background:transparent;border:none;padding:10px;}")
        bl=QHBoxLayout();bl.setSpacing(12)
        self.cancel_btn=ConfirmDialogButton(get_text("btn_cancel"),(100,220,130));self.cancel_btn.clicked.connect(self.reject_animated)
        self.confirm_btn=ConfirmDialogButton(get_text("btn_continue"),(255,80,80));self.confirm_btn.clicked.connect(self.accept_animated)
        bl.addWidget(self.cancel_btn);bl.addWidget(self.confirm_btn)
        cl.addLayout(ic);cl.addWidget(title);cl.addWidget(msg);cl.addLayout(bl)
        self.container.setLayout(cl);main_layout.addWidget(self.container);self.setLayout(main_layout);self.setFixedSize(350,240)
        self.opacity_effect=QGraphicsOpacityEffect(self);self.setGraphicsEffect(self.opacity_effect)
        self.fade_in=QPropertyAnimation(self.opacity_effect,b"opacity");self.fade_in.setDuration(300);self.fade_in.setStartValue(0.0);self.fade_in.setEndValue(1.0)
    def showEvent(self,event):super().showEvent(event);self.fade_in.start()
    def accept_animated(self):self.confirmed=True;self.close_animated()
    def reject_animated(self):self.confirmed=False;self.close_animated()
    def close_animated(self):
        fade=QPropertyAnimation(self.opacity_effect,b"opacity");fade.setDuration(200);fade.setStartValue(1.0);fade.setEndValue(0.0)
        fade.finished.connect(lambda:super(ConfirmDialog,self).accept() if self.confirmed else super(ConfirmDialog,self).reject())
        fade.start();self._fade=fade

class UpdateAppDialog(QDialog):
    def __init__(self,update_info,parent=None):
        super().__init__(parent);self.update_info=update_info
        self.setWindowFlags(Qt.FramelessWindowHint|Qt.Dialog);self.setAttribute(Qt.WA_TranslucentBackground);self.setModal(True);self.confirmed=False
        main_layout=QVBoxLayout();main_layout.setContentsMargins(0,0,0,0)
        self.container=QFrame()
        self.container.setStyleSheet("QFrame{background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 rgba(18,18,22,0.98),stop:1 rgba(16,16,20,0.98));border:2px solid rgba(180,120,255,0.6);border-radius:16px;}")
        cl=QVBoxLayout();cl.setContentsMargins(30,25,30,25);cl.setSpacing(15)
        icon=QLabel("↑");icon.setAlignment(Qt.AlignCenter)
        icon.setStyleSheet("QLabel{color:#B478FF;font-size:28px;font-weight:bold;background:rgba(180,120,255,0.15);border:2px solid rgba(180,120,255,0.4);border-radius:25px;min-width:50px;max-width:50px;min-height:50px;max-height:50px;}")
        ic=QHBoxLayout();ic.addStretch();ic.addWidget(icon);ic.addStretch()
        title=QLabel(get_text("app_update_available"));title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("QLabel{color:#B478FF;font-size:16px;font-weight:bold;background:transparent;border:none;}")
        name=QLabel("Spicetify Manager");name.setAlignment(Qt.AlignCenter)
        name.setStyleSheet("QLabel{color:#FFFFFF;font-size:14px;font-weight:bold;background:transparent;border:none;}")
        ver=QLabel(f"v{update_info['current']}  →  v{update_info['latest']}");ver.setAlignment(Qt.AlignCenter)
        ver.setStyleSheet("QLabel{color:#E0E0E0;font-size:13px;background:rgba(180,120,255,0.1);border:1.5px solid rgba(180,120,255,0.4);border-radius:8px;padding:8px 12px;}")
        bl=QHBoxLayout();bl.setSpacing(12)
        self.cancel_btn=ConfirmDialogButton(get_text("btn_cancel"),(100,220,130));self.cancel_btn.clicked.connect(self.reject_animated)
        self.update_btn=ConfirmDialogButton(get_text("btn_update"),(180,120,255));self.update_btn.clicked.connect(self.accept_animated)
        bl.addWidget(self.cancel_btn);bl.addWidget(self.update_btn)
        cl.addLayout(ic);cl.addWidget(title);cl.addWidget(name);cl.addWidget(ver);cl.addLayout(bl)
        self.container.setLayout(cl);main_layout.addWidget(self.container);self.setLayout(main_layout);self.setFixedSize(380,260)
        self.opacity_effect=QGraphicsOpacityEffect(self);self.setGraphicsEffect(self.opacity_effect)
        self.fade_in=QPropertyAnimation(self.opacity_effect,b"opacity");self.fade_in.setDuration(300);self.fade_in.setStartValue(0.0);self.fade_in.setEndValue(1.0)
    def showEvent(self,event):super().showEvent(event);self.fade_in.start()
    def accept_animated(self):self.confirmed=True;self.close_animated()
    def reject_animated(self):self.confirmed=False;self.close_animated()
    def close_animated(self):
        fade=QPropertyAnimation(self.opacity_effect,b"opacity");fade.setDuration(200);fade.setStartValue(1.0);fade.setEndValue(0.0)
        fade.finished.connect(lambda:super(UpdateAppDialog,self).accept() if self.confirmed else super(UpdateAppDialog,self).reject())
        fade.start();self._fade=fade

class DownloadUpdateDialog(QDialog):
    progress_updated=Signal(int,float,float)
    download_finished=Signal(bool,str)
    def __init__(self,update_info,parent=None):
        super().__init__(parent);self.update_info=update_info
        self.setWindowFlags(Qt.FramelessWindowHint|Qt.Dialog);self.setAttribute(Qt.WA_TranslucentBackground);self.setModal(True)
        self.download_success=False;self.downloaded_path="";self._cancelled=False
        self.progress_updated.connect(self._update_progress);self.download_finished.connect(self._on_download_finished)
        main_layout=QVBoxLayout();main_layout.setContentsMargins(0,0,0,0)
        self.container=QFrame()
        self.container.setStyleSheet("QFrame{background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 rgba(18,18,22,0.96),stop:1 rgba(16,16,20,0.96));border:2px solid rgba(180,120,255,0.6);border-radius:16px;}")
        cl=QVBoxLayout();cl.setContentsMargins(30,25,30,25);cl.setSpacing(15)
        self.icon_label=QLabel("↓");self.icon_label.setAlignment(Qt.AlignCenter)
        self.icon_label.setStyleSheet("QLabel{color:#B478FF;font-size:28px;font-weight:bold;background:rgba(180,120,255,0.15);border:2px solid rgba(180,120,255,0.4);border-radius:25px;min-width:50px;max-width:50px;min-height:50px;max-height:50px;}")
        ic=QHBoxLayout();ic.addStretch();ic.addWidget(self.icon_label);ic.addStretch()
        self.title_label=QLabel(get_text("app_update_downloading"));self.title_label.setAlignment(Qt.AlignCenter)
        self.title_label.setStyleSheet("QLabel{color:#B478FF;font-size:16px;font-weight:bold;background:transparent;border:none;}")
        self.version_label=QLabel(f"Spicetify Manager v{update_info['latest']}");self.version_label.setAlignment(Qt.AlignCenter)
        self.version_label.setStyleSheet("QLabel{color:#FFFFFF;font-size:14px;font-weight:bold;background:transparent;border:none;}")
        self.progress_bar=AnimatedProgressBar("#B478FF")
        self.message_label=QLabel("");self.message_label.setAlignment(Qt.AlignCenter)
        self.message_label.setStyleSheet("QLabel{color:#AAAAAA;font-size:11px;background:transparent;border:none;}");self.message_label.hide()
        self.cancel_btn=ConfirmDialogButton(get_text("btn_cancel"),(255,80,80));self.cancel_btn.clicked.connect(self._cancel_download)
        self.open_folder_btn=ConfirmDialogButton(get_text("btn_open_folder"),(100,220,130));self.open_folder_btn.clicked.connect(self._open_folder);self.open_folder_btn.hide()
        cl.addLayout(ic);cl.addWidget(self.title_label);cl.addWidget(self.version_label)
        cl.addWidget(self.progress_bar);cl.addWidget(self.message_label);cl.addWidget(self.cancel_btn);cl.addWidget(self.open_folder_btn)
        self.container.setLayout(cl);main_layout.addWidget(self.container);self.setLayout(main_layout);self.setFixedSize(380,320)
        self.opacity_effect=QGraphicsOpacityEffect(self);self.setGraphicsEffect(self.opacity_effect)
        self.fade_in=QPropertyAnimation(self.opacity_effect,b"opacity");self.fade_in.setDuration(300);self.fade_in.setStartValue(0.0);self.fade_in.setEndValue(1.0)
    def showEvent(self,event):super().showEvent(event);self.fade_in.start()
    def start_download(self):threading.Thread(target=self._download_worker,daemon=True).start()
    def _download_worker(self):
        new_exe_path=None
        try:
            downloads=os.path.join(os.path.expanduser("~"),"Downloads")
            new_exe_path=os.path.join(downloads,f"SpicetifyManager_v{self.update_info['latest']}.exe")
            url=self.update_info['download_url']
            if requests:
                resp=requests.get(url,stream=True,timeout=300,verify=False);resp.raise_for_status()
                total=int(resp.headers.get('content-length',0));total_mb=total/(1024*1024);downloaded=0
                with open(new_exe_path,'wb') as f:
                    for chunk in resp.iter_content(8192):
                        if self._cancelled:f.close();os.remove(new_exe_path);return
                        if chunk:f.write(chunk);downloaded+=len(chunk)
                        if total:self.progress_updated.emit(int(downloaded*100/total),downloaded/(1024*1024),total_mb)
            else:
                req=Request(url,headers={'User-Agent':'Spicetify-Manager-Updater'})
                with urlopen(req,timeout=300,context=_ssl_context) as resp:
                    total=int(resp.headers.get('Content-Length',0));total_mb=total/(1024*1024);downloaded=0
                    with open(new_exe_path,'wb') as f:
                        while True:
                            if self._cancelled:f.close();os.remove(new_exe_path);return
                            chunk=resp.read(8192)
                            if not chunk:break
                            f.write(chunk);downloaded+=len(chunk)
                            if total:self.progress_updated.emit(int(downloaded*100/total),downloaded/(1024*1024),total_mb)
            if self._cancelled:os.remove(new_exe_path);return
            self.downloaded_path=new_exe_path;self.download_finished.emit(True,new_exe_path)
        except Exception as e:
            if self._cancelled and new_exe_path and os.path.exists(new_exe_path):
                try:os.remove(new_exe_path)
                except:pass
                return
            self.download_finished.emit(False,str(e))
    def _update_progress(self,percent,downloaded_mb,total_mb):self.progress_bar.set_progress(percent);self.progress_bar.set_size(downloaded_mb,total_mb)
    def _on_download_finished(self,success,message):
        if success:
            self.download_success=True;self.title_label.setText(get_text("app_update_downloaded"))
            self.icon_label.setText("✓")
            self.icon_label.setStyleSheet("QLabel{color:#64DC82;font-size:28px;font-weight:bold;background:rgba(100,220,130,0.15);border:2px solid rgba(100,220,130,0.4);border-radius:25px;min-width:50px;max-width:50px;min-height:50px;max-height:50px;}")
            self.title_label.setStyleSheet("QLabel{color:#64DC82;font-size:16px;font-weight:bold;background:transparent;border:none;}")
            current_exe=sys.executable;is_compiled=current_exe.lower().endswith('.exe') and 'python' not in current_exe.lower()
            if is_compiled:self.message_label.setText(get_text("app_click_to_delete"));self.open_folder_btn.setText(get_text("btn_delete_old_open"))
            else:self.message_label.setText(get_text("app_replace_exe"));self.open_folder_btn.setText(get_text("btn_open_folder"))
            self.message_label.show();self.cancel_btn.hide();self.open_folder_btn.show()
        else:
            self.title_label.setText(get_text("app_update_error"));self.icon_label.setText("✗")
            self.icon_label.setStyleSheet("QLabel{color:#FF5050;font-size:28px;font-weight:bold;background:rgba(255,80,80,0.15);border:2px solid rgba(255,80,80,0.4);border-radius:25px;min-width:50px;max-width:50px;min-height:50px;max-height:50px;}")
            self.title_label.setStyleSheet("QLabel{color:#FF5050;font-size:16px;font-weight:bold;background:transparent;border:none;}")
            self.message_label.setText(f"{get_text('console_error')} {message}")
            self.message_label.setStyleSheet("QLabel{color:#FF5050;font-size:11px;background:transparent;border:none;}");self.message_label.show()
            self.cancel_btn.setText(get_text("btn_close"))
    def _cancel_download(self):self._cancelled=True;self._close_animated()
    def _open_folder(self):
        if not self.downloaded_path or not os.path.exists(self.downloaded_path):return
        current_exe=sys.executable;is_compiled=current_exe.lower().endswith('.exe') and 'python' not in current_exe.lower()
        if is_compiled:
            try:
                batch=f'@echo off\nchcp 65001 >nul 2>&1\nset "OLD={current_exe}"\nset "NEW={self.downloaded_path}"\n:wait\ntimeout /t 1 /nobreak >nul\ntasklist /FI "IMAGENAME eq {os.path.basename(current_exe)}" 2>NUL | find /I "{os.path.basename(current_exe)}" >NUL\nif not errorlevel 1 goto wait\ntimeout /t 1 /nobreak >nul\nif exist "%OLD%" del /f /q "%OLD%" 2>nul\ntimeout /t 1 /nobreak >nul\nexplorer /select,"%NEW%"\ndel "%~f0"\n'
                batch_path=os.path.join(os.environ.get('TEMP','.'),'spicetify_update.bat')
                with open(batch_path,'w',encoding='utf-8') as f:f.write(batch)
                subprocess.Popen(['cmd','/c',batch_path],creationflags=subprocess.CREATE_NO_WINDOW,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                self._close_animated();QTimer.singleShot(300,lambda:QApplication.instance().quit())
            except:subprocess.Popen(['explorer','/select,',self.downloaded_path]);self._close_animated()
        else:subprocess.Popen(['explorer','/select,',self.downloaded_path]);self._close_animated()
    def _close_animated(self):
        self.progress_bar.stop()
        fade=QPropertyAnimation(self.opacity_effect,b"opacity");fade.setDuration(200);fade.setStartValue(1.0);fade.setEndValue(0.0)
        fade.finished.connect(self.accept);fade.start();self._fade=fade

class NoUpdateDialog(QDialog):
    def __init__(self,parent=None):
        super().__init__(parent);self.setWindowFlags(Qt.FramelessWindowHint|Qt.Dialog)
        self.setAttribute(Qt.WA_TranslucentBackground);self.setModal(True);self._checking=False;self._rotation=0
        main_layout=QVBoxLayout();main_layout.setContentsMargins(0,0,0,0)
        self.container=QFrame()
        self.container.setStyleSheet("QFrame{background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 rgba(18,18,22,0.98),stop:1 rgba(16,16,20,0.98));border:2px solid rgba(180,120,255,0.6);border-radius:16px;}")
        cl=QVBoxLayout();cl.setContentsMargins(30,25,30,25);cl.setSpacing(15)
        self.icon_label=QLabel("⟳");self.icon_label.setAlignment(Qt.AlignCenter)
        self.icon_label.setStyleSheet("QLabel{color:#B478FF;font-size:28px;font-weight:bold;background:rgba(180,120,255,0.15);border:2px solid rgba(180,120,255,0.4);border-radius:25px;min-width:50px;max-width:50px;min-height:50px;max-height:50px;}")
        ic=QHBoxLayout();ic.addStretch();ic.addWidget(self.icon_label);ic.addStretch()
        self.title_label=QLabel(get_text("app_checking_updates"));self.title_label.setAlignment(Qt.AlignCenter)
        self.title_label.setStyleSheet("QLabel{color:#B478FF;font-size:16px;font-weight:bold;background:transparent;border:none;}")
        self.message_label=QLabel(get_text("app_please_wait"));self.message_label.setAlignment(Qt.AlignCenter)
        self.message_label.setStyleSheet("QLabel{color:#E0E0E0;font-size:13px;background:transparent;border:none;}")
        self.version_label=QLabel(f"{get_text('app_current_version')} v{APP_VERSION}");self.version_label.setAlignment(Qt.AlignCenter)
        self.version_label.setStyleSheet("QLabel{color:#AAAAAA;font-size:11px;background:rgba(180,120,255,0.1);border:1.5px solid rgba(180,120,255,0.3);border-radius:6px;padding:6px 10px;}")
        self.close_btn=ConfirmDialogButton(get_text("btn_close"),(100,220,130));self.close_btn.clicked.connect(self._close_animated);self.close_btn.hide()
        cl.addLayout(ic);cl.addWidget(self.title_label);cl.addWidget(self.message_label);cl.addWidget(self.version_label);cl.addWidget(self.close_btn)
        self.container.setLayout(cl);main_layout.addWidget(self.container);self.setLayout(main_layout);self.setFixedSize(350,260)
        self.opacity_effect=QGraphicsOpacityEffect(self);self.setGraphicsEffect(self.opacity_effect)
        self.fade_in=QPropertyAnimation(self.opacity_effect,b"opacity");self.fade_in.setDuration(300);self.fade_in.setStartValue(0.0);self.fade_in.setEndValue(1.0)
        self._rotation_timer=QTimer();self._rotation_timer.timeout.connect(self._rotate_icon)
    def showEvent(self,event):super().showEvent(event);self.fade_in.start()
    def set_checking(self):self._checking=True;self._rotation_timer.start(FPS_75)
    def _rotate_icon(self):
        if not self._checking:return
        self._rotation=(self._rotation+8)%360
        b=0.7+0.3*abs(math.sin(math.radians(self._rotation)))
        r,g,bl=int(180*b),int(120*b),int(255*b)
        self.icon_label.setStyleSheet(f"QLabel{{color:rgb({r},{g},{bl});font-size:28px;font-weight:bold;background:rgba(180,120,255,0.15);border:2px solid rgba(180,120,255,0.4);border-radius:25px;min-width:50px;max-width:50px;min-height:50px;max-height:50px;}}")
    def set_no_update(self):
        self._checking=False;self._rotation_timer.stop()
        self.icon_label.setText("✓")
        self.icon_label.setStyleSheet("QLabel{color:#64DC82;font-size:28px;font-weight:bold;background:rgba(100,220,130,0.15);border:2px solid rgba(100,220,130,0.4);border-radius:25px;min-width:50px;max-width:50px;min-height:50px;max-height:50px;}")
        self.title_label.setText(get_text("app_no_updates"))
        self.title_label.setStyleSheet("QLabel{color:#64DC82;font-size:16px;font-weight:bold;background:transparent;border:none;}")
        self.message_label.setText(get_text("app_latest_version"));self.close_btn.show()
    def _close_animated(self):
        self._rotation_timer.stop()
        fade=QPropertyAnimation(self.opacity_effect,b"opacity");fade.setDuration(200);fade.setStartValue(1.0);fade.setEndValue(0.0)
        fade.finished.connect(self.accept);fade.start();self._fade=fade


# ============================================================
# ГЛАВНОЕ ОКНО
# ============================================================

class SpicetifyManager(QMainWindow):
    log_signal=Signal(str,str)
    header_signal=Signal(str,str,str)
    status_update_signal=Signal()
    buttons_enable_signal=Signal(bool)
    loading_signal=Signal(bool,str,str,str)
    show_update_dialog_signal=Signal(dict)
    def __init__(self):
        super().__init__()
        self.current_version=self.latest_version=self.latest_version_date=None
        self.is_installed=self.update_available=False;self._check_dialog=None
        self.log_signal.connect(self._write_console_safe)
        self.header_signal.connect(self._write_header_safe)
        self.status_update_signal.connect(self.update_status_label)
        self.buttons_enable_signal.connect(self._set_buttons_enabled)
        self.loading_signal.connect(self._set_loading)
        self.show_update_dialog_signal.connect(self._show_update_dialog)
        self.setup_ui()
        self.opacity_effect=QGraphicsOpacityEffect(self);self.setGraphicsEffect(self.opacity_effect)
        self.fade_in=QPropertyAnimation(self.opacity_effect,b"opacity");self.fade_in.setDuration(600);self.fade_in.setStartValue(0.0);self.fade_in.setEndValue(1.0);self.fade_in.start()
        QTimer.singleShot(500,self.check_app_updates);QTimer.singleShot(300,self.check_version)
    def setup_ui(self):
        self.setWindowTitle(get_text("window_title"));self.setFixedSize(700,620);self.setWindowIcon(QIcon(":/assets/spicetify.png"))
        central=QWidget();self.setCentralWidget(central)
        main_layout=QVBoxLayout();main_layout.setContentsMargins(25,25,25,25);main_layout.setSpacing(15)
        # Верхняя панель
        top_layout=QHBoxLayout();title_container=QWidget()
        title_layout=QHBoxLayout();title_layout.setContentsMargins(0,0,0,0);title_layout.setSpacing(15)
        self.flame_icon=FlameIcon()
        self.title_label=QLabel(get_text("app_title"));self.title_label.setFont(QFont("Segoe UI",22,QFont.Bold))
        self.title_label.setStyleSheet("color: #64DC82; letter-spacing: 1px;")
        title_layout.addWidget(self.flame_icon);title_layout.addWidget(self.title_label);title_layout.addStretch()
        title_container.setLayout(title_layout)
        self.lang_toggle=LanguageToggle();self.lang_toggle.language_changed.connect(self.update_language)
        top_layout.addWidget(title_container);top_layout.addStretch();top_layout.addWidget(self.lang_toggle,0,Qt.AlignTop)
        main_layout.addLayout(top_layout)
        # Статус
        self.status_frame=QFrame();self.status_frame.setFixedHeight(95)
        self.status_frame.setStyleSheet("QFrame{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 rgba(25,25,30,0.9),stop:1 rgba(30,30,35,0.9));border:2px solid rgba(100,220,130,0.4);border-radius:12px;}")
        status_outer=QHBoxLayout();status_outer.setContentsMargins(18,12,18,12)
        self.status_inner_frame=QFrame()
        self.status_inner_frame.setStyleSheet("QFrame{background:rgba(20,20,25,0.6);border:2px solid rgba(100,220,130,0.3);border-radius:8px;}")
        status_inner=QHBoxLayout();status_inner.setContentsMargins(12,8,12,8);status_inner.setSpacing(15)
        self.status_label=QLabel(get_text("status_loading"));self.status_label.setTextFormat(Qt.RichText)
        font=QFont("Cascadia Code",9)
        if not QFont("Cascadia Code").exactMatch():font=QFont("Consolas",9)
        self.status_label.setFont(font);self.status_label.setStyleSheet("color:#E0E0E0;background:transparent;border:none;");self.status_label.setWordWrap(True)
        self.update_indicator=UpdateIndicator()
        status_inner.addWidget(self.status_label);status_inner.addStretch();status_inner.addWidget(self.update_indicator,0,Qt.AlignRight|Qt.AlignVCenter)
        self.status_inner_frame.setLayout(status_inner);status_outer.addWidget(self.status_inner_frame);self.status_frame.setLayout(status_outer)
        main_layout.addWidget(self.status_frame)
        # Консоль
        self.console=ModernConsole();self.console.setMinimumHeight(250);self.console.setSizePolicy(QSizePolicy.Expanding,QSizePolicy.Expanding)
        main_layout.addWidget(self.console,1)
        # Кнопки
        btn_container=QWidget();btn_container.setFixedHeight(65)
        btn_layout=QHBoxLayout();btn_layout.setContentsMargins(0,0,0,0);btn_layout.setSpacing(12)
        self.install_btn=GlowButton(get_text("btn_install"),(100,220,130))
        self.reinstall_btn=GlowButton(get_text("btn_reinstall"),(230,120,80))
        self.update_btn=GlowButton(get_text("btn_update"),(255,180,50))
        self.check_btn=GlowButton(get_text("btn_check"),(34,211,238))
        self.delete_btn=GlowButton(get_text("btn_delete"),(255,80,80))
        self.install_btn.clicked.connect(self.install_spicetify);self.reinstall_btn.clicked.connect(self.reinstall_spicetify)
        self.update_btn.clicked.connect(self.update_spicetify);self.check_btn.clicked.connect(self.check_version)
        self.delete_btn.clicked.connect(self.delete_spicetify)
        btn_layout.addWidget(self.install_btn);btn_layout.addWidget(self.delete_btn);btn_layout.addWidget(self.reinstall_btn)
        btn_layout.addWidget(self.update_btn);btn_layout.addWidget(self.check_btn)
        btn_container.setLayout(btn_layout);main_layout.addWidget(btn_container)
        # Футер
        bottom_layout=QHBoxLayout();bottom_layout.setContentsMargins(5,1,5,3)
        left_footer=QVBoxLayout();left_footer.setSpacing(2)
        self.copyright_label=QLabel(get_text("footer_copyright"));self.copyright_label.setFont(QFont("Segoe UI",8));self.copyright_label.setStyleSheet("color:#888888;")
        left_footer.addWidget(self.copyright_label)
        self.link_label=LinkLabel('');left_footer.addWidget(self.link_label)
        bottom_layout.addLayout(left_footer);bottom_layout.addStretch()
        self.version_btn=VersionButton(f"v{APP_VERSION}");self.version_btn.clicked.connect(self._on_version_clicked)
        bottom_layout.addWidget(self.version_btn);main_layout.addLayout(bottom_layout)
        central.setLayout(main_layout)
        self.setStyleSheet("QMainWindow{background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #0F0F12,stop:0.5 #1A1A1E,stop:1 #15151A);}QLabel{color:#FFFFFF;}")
        self.particle_overlay=ParticleOverlay(self);self.particle_overlay.setGeometry(0,0,self.width(),self.height());self.particle_overlay.raise_()
    def update_language(self,lang):
        set_current_language(lang);self.console.clear();self.refresh_all_texts();QTimer.singleShot(100,self.check_version)
    def refresh_all_texts(self):
        self.setWindowTitle(get_text("window_title"));self.title_label.setText(get_text("app_title"))
        self.install_btn.setText(get_text("btn_install"));self.reinstall_btn.setText(get_text("btn_reinstall"))
        self.update_btn.setText(get_text("btn_update"));self.check_btn.setText(get_text("btn_check"));self.delete_btn.setText(get_text("btn_delete"))
        self.copyright_label.setText(get_text("footer_copyright"));self.link_label.update_link_style();self.update_status_label()
    def resizeEvent(self,event):
        super().resizeEvent(event)
        if hasattr(self,'particle_overlay'):self.particle_overlay.setGeometry(0,0,self.width(),self.height())
    def showEvent(self,event):
        super().showEvent(event)
        if hasattr(self,'particle_overlay'):
            for btn in [self.install_btn,self.reinstall_btn,self.update_btn,self.check_btn,self.delete_btn,self.version_btn]:self.particle_overlay.register_button(btn)
            self.particle_overlay.register_version_button(self.version_btn)
    def update_status_frame_style(self,status_type="installed"):
        colors={"not_installed":(255,80,80),"update_available":(255,180,50)}
        r,g,b=colors.get(status_type,(100,220,130))
        self.status_frame.setStyleSheet(f"QFrame{{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 rgba(25,25,30,0.9),stop:1 rgba(30,30,35,0.9));border:2px solid rgba({r},{g},{b},0.4);border-radius:12px;}}")
        self.status_inner_frame.setStyleSheet(f"QFrame{{background:rgba(20,20,25,0.6);border:2px solid rgba({r},{g},{b},0.3);border-radius:8px;}}")
    def _write_console_safe(self,text,color):self.console.add_message(text,color)
    def _write_header_safe(self,text,color,icon):self.console.add_header(text,color,icon if icon else "")
    def write_console(self,text,color="green"):self.log_signal.emit(text,color)
    def write_header(self,text,color="#64DC82",icon=None):self.header_signal.emit(text,color,icon if icon else "")
    def _format_status_dot(self,color):return f'<span style="font-family:Verdana,sans-serif;font-size:14px;color:{color};">●</span>'
    def update_status_label(self):
        if self.is_installed:
            if self.update_available:
                dot=self._format_status_dot("#FFB432")
                status=f"{dot} <span style='color:#FFB432;'>{get_text('status_update_available')}</span><br>"
                status+=f"<span style='color:#FFB432;'>{get_text('status_version')}: {self.current_version}</span><br>"
                if self.latest_version:
                    latest=f"{get_text('status_latest')}: {self.latest_version}"
                    if self.latest_version_date:latest+=f" ({self.latest_version_date})"
                    status+=f"<span style='color:#FFB432;white-space:nowrap;'>{latest}</span>"
                self.update_indicator.set_status("update_available");self.update_status_frame_style("update_available")
            else:
                dot=self._format_status_dot("#64DC82")
                status=f"{dot} <span style='color:#64DC82;'>{get_text('status_installed')}</span><br>"
                status+=f"<span style='color:#64DC82;'>{get_text('status_version')}: {self.current_version}</span><br>"
                if self.latest_version:
                    latest=f"{get_text('status_latest')}: {self.latest_version}"
                    if self.latest_version_date:latest+=f" ({self.latest_version_date})"
                    status+=f"<span style='color:#64DC82;white-space:nowrap;'>{latest}</span>"
                self.update_indicator.set_status("up_to_date");self.update_status_frame_style("installed")
        else:
            dot=self._format_status_dot("#FF8080")
            status=f"{dot} <span style='color:#FF8080;'>{get_text('status_not_installed')}</span><br>"
            if self.latest_version:
                avail=f"{get_text('status_available_version')}: {self.latest_version}"
                if self.latest_version_date:avail+=f" ({self.latest_version_date})"
                status+=f"<span style='color:#FF8080;white-space:nowrap;'>{avail}</span>"
            self.update_indicator.set_status("not_installed");self.update_status_frame_style("not_installed")
        self.status_label.setText(status);self.update_button_states()
    def update_button_states(self):
        if self.is_installed:self.install_btn.setEnabled(False);self.reinstall_btn.setEnabled(True);self.update_btn.setEnabled(True);self.delete_btn.setEnabled(True)
        else:self.install_btn.setEnabled(True);self.reinstall_btn.setEnabled(False);self.update_btn.setEnabled(False);self.delete_btn.setEnabled(False)
    def _fetch_latest_version(self):
        try:
            url="https://api.github.com/repos/spicetify/cli/releases/latest"
            if requests:r=requests.get(url,timeout=10,headers={'User-Agent':'Spicetify-Manager-Python'},verify=False);r.raise_for_status();data=r.json()
            else:
                req=Request(url,headers={'User-Agent':'Spicetify-Manager-Python'})
                with urlopen(req,timeout=10,context=_ssl_context) as resp:data=json.loads(resp.read().decode('utf-8'))
            version=data.get('tag_name','').replace('v','');published=data.get('published_at','')
            if published:
                from datetime import datetime
                try:dt=datetime.strptime(published,"%Y-%m-%dT%H:%M:%SZ");self.latest_version_date=dt.strftime("%d.%m.%Y")
                except:pass
            return version if version else None
        except Exception as e:self.write_console(f"{get_text('console_error')} {str(e)}","red");return None
    def check_version(self):
        self.console.clear();self.disable_buttons();self.write_header(get_text("console_check_header"),"#22D3EE")
        threading.Thread(target=self._check_version_worker,daemon=True).start()
    def _check_version_worker(self):
        sp=os.path.join(os.getenv("LOCALAPPDATA"),"spicetify","spicetify.exe")
        self.is_installed=False;self.current_version=None
        if os.path.exists(sp):
            try:
                self.write_console(get_text("console_checking_version"),"gray")
                flags=subprocess.CREATE_NO_WINDOW if sys.platform=='win32' else 0
                result=subprocess.run([sp,"--version"],capture_output=True,text=True,timeout=5,creationflags=flags)
                match=re.search(r'(\d+\.\d+\.\d+)',result.stdout)
                if match:self.current_version=match.group(1);self.is_installed=True;self.write_console(f"{get_text('console_version_installed')} {self.current_version}","success")
                else:self.write_console(get_text("console_spicetify_found_no_response"),"warning")
            except:self.write_console(get_text("console_spicetify_damaged"),"warning")
        else:self.write_console(get_text("console_spicetify_not_installed"),"warning")
        self.write_console(get_text("console_checking_latest"),"gray")
        self.latest_version=self._fetch_latest_version()
        if self.latest_version:
            date_str=f" ({self.latest_version_date})" if self.latest_version_date else ""
            self.write_console(f"{get_text('console_latest_version')} {self.latest_version}{date_str}","success")
            if self.is_installed and self.current_version:
                self.update_available=self.current_version!=self.latest_version
                if self.update_available:self.write_console(get_text("console_update_available"),"warning")
                else:self.write_console(get_text("console_latest_installed"),"success")
        else:self.write_console(get_text("console_fetch_error"),"warning")
        self.status_update_signal.emit();self.enable_buttons()
    def install_spicetify(self):
        if self.is_installed:self.write_console(get_text("console_already_installed"),"warning");return
        dialog=ConfirmDialog(get_text("dialog_install_question"),get_text("dialog_confirm_install"),"green",self)
        dialog.exec();self._restart_animation_timers()
        if not dialog.confirmed:return
        self.console.clear();self.disable_buttons();self.write_header(get_text("console_install_header"),"#64DC82")
        self.write_console(get_text("console_starting_script"),"gray");self.write_console(get_text("console_powershell_confirm"),"warning")
        threading.Thread(target=self._install_worker,daemon=True).start()
    def _install_worker(self):
        try:
            self.loading_signal.emit(True,get_text("loading_install"),"cubes","#64DC82")
            command=("[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; "
                "iwr -useb https://raw.githubusercontent.com/spicetify/cli/main/install.ps1 | iex; "
                "Write-Host ''; Write-Host 'Press any key to close...' -ForegroundColor Green; "
                "$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')")
            p=start_powershell_trustlevel(command,creationflags=subprocess.CREATE_NEW_CONSOLE)
            self.write_console(get_text("console_waiting_install"),"gray")
            while p.poll() is None:time.sleep(0.3)
            self.loading_signal.emit(False,"","","");self.write_console(get_text("console_window_closed"),"success");time.sleep(1)
            if os.path.exists(os.path.join(os.getenv("LOCALAPPDATA"),"spicetify","spicetify.exe")):
                self.write_console(get_text("console_install_success"),"success");self._check_version_worker()
            else:self.write_console(get_text("console_install_failed"),"error")
        except Exception as e:self.write_console(f"{get_text('console_error')} {str(e)}","error");self.loading_signal.emit(False,"","","")
        self.enable_buttons()
    def reinstall_spicetify(self):
        dialog=ConfirmDialog(get_text("dialog_reinstall_question"),get_text("dialog_confirm_reinstall"),"orange",self)
        dialog.exec();self._restart_animation_timers()
        if not dialog.confirmed:return
        self.console.clear();self.disable_buttons();self.write_header(get_text("console_reinstall_header"),"#E67850")
        self.write_console(get_text("console_starting_script"),"gray");self.write_console(get_text("console_powershell_confirm"),"warning")
        threading.Thread(target=self._reinstall_worker,daemon=True).start()
    def _reinstall_worker(self):
        try:
            self.loading_signal.emit(True,get_text("loading_reinstall"),"cubes","#E67850")
            command=("[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; "
                "iwr -useb https://raw.githubusercontent.com/spicetify/cli/main/install.ps1 | iex; "
                "Write-Host ''; Write-Host 'Press any key to close...' -ForegroundColor Green; "
                "$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')")
            p=start_powershell_trustlevel(command,creationflags=subprocess.CREATE_NEW_CONSOLE)
            self.write_console(get_text("console_waiting_reinstall"),"gray")
            while p.poll() is None:time.sleep(0.3)
            self.loading_signal.emit(False,"","","");self.write_console(get_text("console_reinstall_window_closed"),"success");time.sleep(1)
            self.write_console(get_text("console_reinstall_success"),"success");self._check_version_worker()
        except Exception as e:self.write_console(f"{get_text('console_error')} {str(e)}","error")
        self.loading_signal.emit(False,"","","");self.enable_buttons()
    def update_spicetify(self):
        sp=os.path.join(os.getenv("LOCALAPPDATA"),"spicetify","spicetify.exe")
        if not os.path.exists(sp):self.write_console(get_text("console_spicetify_not_found"),"error");self.write_console(get_text("console_install_first"),"warning");return
        self.console.clear();self.disable_buttons();self.write_header(get_text("console_update_header"),"#FFB432")
        self.write_console(get_text("console_starting_update"),"gray");self.write_console(get_text("console_powershell_confirm"),"warning")
        threading.Thread(target=self._update_worker,args=(sp,),daemon=True).start()
    def _update_worker(self,sp):
        try:
            self.loading_signal.emit(True,get_text("loading_update"),"cubes","#FFB432")
            command=(f"& '{sp}' update --bypass-admin; Write-Host ''; Write-Host 'Press any key to close...' -ForegroundColor Green; "
                "$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')")
            p=start_powershell_trustlevel(command,creationflags=subprocess.CREATE_NEW_CONSOLE)
            self.write_console(get_text("console_waiting_update"),"gray")
            while p.poll() is None:time.sleep(0.3)
            self.write_console(get_text("console_update_window_closed"),"success")
            self.write_console(get_text("console_update_complete"),"success");time.sleep(1);self._check_version_worker()
        except Exception as e:self.write_console(f"{get_text('console_error')} {str(e)}","error")
        self.loading_signal.emit(False,"","","");self.enable_buttons()
    def delete_spicetify(self):
        dialog=ConfirmDialog(get_text("dialog_delete_question"),get_text("dialog_confirm_delete"),"red",self)
        dialog.exec();self._restart_animation_timers()
        if not dialog.confirmed:return
        self.console.clear();self.disable_buttons();self.write_header(get_text("console_delete_header"),"#FF5050")
        self.write_console(get_text("console_starting_delete"),"gray")
        threading.Thread(target=self._delete_worker,daemon=True).start()
    def _delete_worker(self):
        import shutil
        try:
            self.loading_signal.emit(True,get_text("loading_delete"),"cubes","#FF5050")
            self.write_console(get_text("console_restoring_spotify"),"gray")
            try:
                run_powershell_trustlevel("spicetify restore --bypass-admin",timeout=30,creationflags=subprocess.CREATE_NO_WINDOW)
                self.write_console(get_text("console_spotify_restored"),"success")
            except Exception as e:self.write_console(f"{get_text('console_restore_error')} {str(e)}","warning")
            time.sleep(1);self.write_console(get_text("console_deleting_files"),"gray")
            appdata=os.path.join(os.getenv("APPDATA"),"spicetify");localappdata=os.path.join(os.getenv("LOCALAPPDATA"),"spicetify")
            for path,err_key in [(appdata,"console_delete_appdata_error"),(localappdata,"console_delete_localappdata_error")]:
                try:
                    if os.path.exists(path):shutil.rmtree(path);self.write_console(f"{get_text('console_deleted')} {path}","success")
                    else:self.write_console(f"{get_text('console_folder_not_found')} {path}","warning")
                except Exception as e:self.write_console(f"{get_text(err_key)} {str(e)}","warning")
            self.write_console(get_text("console_delete_success"),"success");self.write_console(get_text("console_files_cleaned"),"success")
            time.sleep(1);self._check_version_worker()
        except Exception as e:self.write_console(f"{get_text('console_error')} {str(e)}","error")
        self.loading_signal.emit(False,"","","");self.enable_buttons()
    def _set_buttons_enabled(self,enabled):
        self.check_btn.setEnabled(enabled);self.delete_btn.setEnabled(enabled);self.lang_toggle.setEnabled(enabled)
        if enabled:self.update_button_states()
        else:self.install_btn.setEnabled(False);self.reinstall_btn.setEnabled(False);self.update_btn.setEnabled(False)
    def _set_loading(self,visible,text="",loading_type="spinner",color="#64DC82"):
        if visible:self.console.show_loading(text,loading_type,color)
        else:self.console.hide_loading()
    def disable_buttons(self):self.buttons_enable_signal.emit(False)
    def enable_buttons(self):self.buttons_enable_signal.emit(True)
    def check_app_updates(self):threading.Thread(target=self._check_app_updates_worker,daemon=True).start()
    def _check_app_updates_worker(self):
        update_info=check_app_update()
        if update_info and update_info.get('update_available') and update_info.get('download_url'):self.show_update_dialog_signal.emit(update_info)
        else:QTimer.singleShot(0,lambda:self.version_btn.set_update_available(False,None))
    def _show_update_dialog(self,update_info):
        if hasattr(self,'_check_dialog') and self._check_dialog is not None:self._handle_version_check_result(update_info);return
        if not update_info or not update_info.get('update_available') or not update_info.get('download_url'):self.version_btn.set_update_available(False,None);return
        self.version_btn.set_update_available(True,update_info)
        dialog=UpdateAppDialog(update_info,self);dialog.show();dialog.raise_();result=dialog.exec()
        self._restart_animation_timers()
        if dialog.confirmed:self._perform_app_update(update_info)
    def _restart_animation_timers(self):
        if hasattr(self,'particle_overlay'):self.particle_overlay.animation_timer.stop();self.particle_overlay.animation_timer.start(FPS_75)
        if hasattr(self,'update_indicator'):self.update_indicator.timer.stop();self.update_indicator.timer.start(FPS_75)
    def _perform_app_update(self,update_info):
        dialog=DownloadUpdateDialog(update_info,self);dialog.show();dialog.raise_();dialog.start_download();dialog.exec();self._restart_animation_timers()
    def _on_version_clicked(self):
        if self.version_btn.has_update and self.version_btn.cached_update_info:self._show_update_dialog(self.version_btn.cached_update_info)
        else:self._check_version_and_show_dialog()
    def _check_version_and_show_dialog(self):
        self._check_dialog=NoUpdateDialog(self);self._check_dialog.set_checking();self._check_dialog.show();self._check_dialog.raise_()
        def worker():
            info=check_app_update();self.show_update_dialog_signal.emit(info if info else {'update_available':False})
        threading.Thread(target=worker,daemon=True).start()
    def _handle_version_check_result(self,update_info):
        if not hasattr(self,'_check_dialog') or self._check_dialog is None:return
        if update_info and update_info.get('update_available') and update_info.get('download_url'):
            self._check_dialog.close();self._check_dialog=None;self._restart_animation_timers()
            self.version_btn.set_update_available(True,update_info);self._show_update_dialog(update_info)
        else:self._check_dialog.set_no_update()


if __name__=="__main__":
    app=QApplication(sys.argv);app.setStyle("Fusion");app.setWindowIcon(QIcon(":/assets/spicetify.png"))
    palette=QPalette()
    palette.setColor(QPalette.Window,QColor(15,15,18));palette.setColor(QPalette.WindowText,Qt.white)
    palette.setColor(QPalette.Base,QColor(10,10,12));palette.setColor(QPalette.Text,QColor(224,224,224))
    palette.setColor(QPalette.Button,QColor(30,30,35));palette.setColor(QPalette.ButtonText,Qt.white)
    palette.setColor(QPalette.Link,QColor(100,220,130));palette.setColor(QPalette.Highlight,QColor(100,220,130))
    app.setPalette(palette)
    window=SpicetifyManager();window.show();sys.exit(app.exec())
