import sys
import os
from enum import Enum
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import Qt, QUrl,QTimer
from PyQt5 import QtCore, QtWidgets

from PyQt5.QtWidgets import (
    QDesktopWidget, QApplication, QMainWindow, QWidget, QTabBar, QToolBar,
    QAction, QLineEdit, QTabWidget, QPushButton, QVBoxLayout, QToolButton, QHBoxLayout
)
from PyQt5.QtWebEngineWidgets import QWebEngineView, QWebEnginePage, QWebEngineSettings
import qdarkstyle
import atexit
from PyQt5.QtWidgets import QMessageBox
from PyQt5.QtWidgets import QMainWindow, QVBoxLayout, QMessageBox, QWidget, QTimer, QApplication
from PyQt5.QtCore import Qt

class WebPage(QWebEnginePage):
    def certificateError(self, error):
        return True
def modify_number(input_number):
    if input_number > 1900:
        return input_number / 1.2
    if input_number > 1870:
        return input_number / 1.3
    elif input_number > 1770:
        return input_number / 1.4
    elif input_number > 1670:
        return input_number / 1.5
    elif input_number > 1570:
        return input_number / 1.6
    elif input_number > 1470:
        return input_number / 1.8
    elif input_number > 1370:
        return input_number / 2.2
    elif input_number > 1270:
        return input_number / 2.4
    elif input_number > 1170:
        return input_number / 2.6
    elif input_number > 1070:
        return input_number / 2.8
    elif input_number > 970:
        return input_number / 3.2
    elif input_number > 870:
        return input_number / 3.4
    elif input_number > 770:
        return input_number / 3.6
    else:
        return input_number // 3.8
class Urls(Enum):
    DEFAULT_HOME = "https://duckduckgo.com/"
    SHODAN = 'https://www.shodan.io/'
    DRONEBL = 'https://dronebl.org/lookup?'
    DNSDUMPSTER = 'https://dnsdumpster.com/'
    DEHASHED = 'https://www.dehashed.com/'
    CYBERCRIME = 'https://cybercrime-tracker.net/'
    ONYPHE = 'https://www.onyphe.io/'
    AHMIA = 'https://ahmia.fi/'
    ARCHIVE = 'https://archive.org/search?'
    ARIN = 'https://search.arin.net/arin/'
    BGPVIEW = 'https://bgpview.io/'
    CERTIFICATE = 'https://crt.sh/'
    THREAT_CROWD = "http://ci-www.threatcrowd.org/"
    VIRUS_TOTAL = "https://www.virustotal.com/"
    MIT_OCW = "https://ocw.mit.edu/"
    HACKER_ONE = "https://www.hackerone.com/"
    CYBRARY = "https://www.cybrary.it/"
    OWASP_TOP_10 = "https://owasp.org/Top10/"
    HACKER_NEWS = "https://thehackernews.com/"
    KREBS_ON_SECURITY = "https://krebsonsecurity.com/"
    TECHCRUNCH = "https://techcrunch.com/"
    GITHUB = "https://github.com/"
    STACK_OVERFLOW = "https://stackoverflow.com/"
    REDDIT_INFOSEC = "https://www.reddit.com/r/Infosec/"
    PROJECT_GUTENBERG = "https://dev.gutenberg.org/"
    METAEXPLOIT_RAPID7 = "https://www.rapid7.com/products/metasploit/"
    HACKER_NMAP = "https://hackertarget.com/nmap-online-port-scanner/"
    ZDNET_SECURITY = "https://www.zdnet.com/topic/security/"
    SECURITY_WEEK = "https://www.securityweek.com/"
    HACKER_NEWS_YCOMBINATOR = "https://news.ycombinator.com/"
    DARK_READING = "https://www.darkreading.com/"
    WHOIS_LOOKUP = "https://who.is/"
    URL_VOID = "https://www.urlvoid.com/"
    NIST_NVD = "https://nvd.nist.gov/vuln/search"
    INTERNET_ARCHIVE = "https://archive.org/"
    DNS_DUMPSTER = "https://dnsdumpster.com/"
    EXPLOIT_DB = "https://www.exploit-db.com/"
    MITRE_ATTACK = "https://attack.mitre.org/"
    OSVF = "https://openssf.org/"
    TENABLE = "https://www.tenable.com/plugins"
    SANS_INSTITUTE = "https://www.sans.org/"


class Navigator:
    @staticmethod
    def navigate(web_view, url):
        try:
            web_view.setUrl(QUrl(url))
        except (ValueError, TypeError) as e:
            print(f"Error navigating to {url}: {e}")


class TabWidget(QWidget):
    urlChanged = QtCore.pyqtSignal(QUrl)

    def __init__(self, url=None):
        super().__init__()
        self.webView = QWebEngineView()
        
        # Load the welcome page or default message
        welcome_file_path = os.path.abspath("welcome.html")
        if os.path.exists(welcome_file_path):
            welcome_file_url = QUrl.fromLocalFile(welcome_file_path)
            self.webView.setUrl(welcome_file_url)
        else:
            self.load_default_welcome()

        layout = QVBoxLayout(self)
        layout.addWidget(self.webView)

        self.webView.urlChanged.connect(self.handleUrlChanged)

    def load_default_welcome(self):
        html_content = """
<html>
<head>
    <style>
        body {
            background: url('icons/usmarker.png') no-repeat center center fixed;
            background-size: cover;
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            color: white;
        }
        .card {
            background-color: rgba(31, 31, 31, 0.9);
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
            text-align: center;
            max-width: 400px;
            width: 80%;
        }
        h1 {
            color: #AB7ADF;
            margin-bottom: 20px;
        }
        p {
            margin: 0;
        }
    </style>
</head>
<body>
    <div class="card">
        <h1>Welcome to Units Browser!</h1>
        <p>Start your secure browsing journey by opening a new tab or navigating to a URL.</p>
    </div>
</body>
</html>
"""

        self.webView.setHtml(html_content)
        self.page.linkHovered.connect(self.handleLinkHovered)


    def handleUrlChanged(self, url):
        self.urlChanged.emit(url)

    def handleLinkHovered(self, url):
        modifiers = QApplication.keyboardModifiers()
        openInNewTab = modifiers == Qt.ControlModifier or modifiers == Qt.ShiftModifier

        if openInNewTab:
            self.urlChanged.emit(QUrl(url))


class ClosableTabWidget(QTabWidget):
    def __init__(self, parent=None):
        super(ClosableTabWidget, self).__init__(parent)
        self.setTabsClosable(True)
        self.tabCloseRequested.connect(self.closeTab)

    def createTab(self, url=None, tabName=None, tabIndex=None):
        browserTab = TabWidget(url)
        index = self.insertTab(tabIndex if tabIndex is not None else self.count(
        ), browserTab, tabName if tabName else "Destroyer")

        closeButton = QPushButton("❌")
        closeButton.clicked.connect(
            lambda _, index=index: self.closeTab(index))
        self.tabBar().setTabButton(index, QTabBar.RightSide, closeButton)

        browserTab.urlChanged.connect(self.updateUrl)
        browserTab.webView.titleChanged.connect(
            lambda title, index=index: self.setTabText(index, title))

    def closeTab(self, index):
        widget = self.widget(index)
        if widget:
            widget.deleteLater()
            self.removeTab(index)

    def updateUrl(self, url):
        index = self.indexOf(self.sender().parent())
        self.setTabText(index, url.host())


class AppMainWindow(QMainWindow):
    def __init__(self):
        super(AppMainWindow, self).__init__()

        settings = QWebEngineSettings.globalSettings()
        settings.setAttribute(QWebEngineSettings.LocalStorageEnabled, False)
        settings.setAttribute(QWebEngineSettings.PluginsEnabled, False)
        self.statusBar = self.statusBar()
        self.tabs = ClosableTabWidget()
        
        tab_stylesheet = """
        QTabBar::tab {
        background: #1F1F1F; /* Background color of the tab */
        color: white; /* Text color */
        
        border-radius: 4px; /* Rounded corners */
        padding: 6px 12px; /* Padding inside the tabs */
        margin: 2px; /* Space between tabs */
        }

QTabBar::tab:selected {
    background: #444; /* Background for selected tab */
    font-weight: small; /* Highlight selected tab */
    color: #fff; /* white text color for active tab */
}

QTabBar::tab:hover {
    background: #555; /* Slightly lighter background on hover */
    color: #FFF; /* White text color */
}

QTabWidget::pane {
    border: 1px solid #3e3e42; /* Border around the tab content */
    background-color: #1e1e1e; /* Dark background for content area */
}

QTabBar::close-button {
    image: url(icons/close.svg); /* Path to your close icon */
    subcontrol-position: right; /* Position the close button */
    margin: 2px; /* Space around the close button */
}
QTabBar::close-button:hover {
    background: #FF4444; /* Red background on hover */
    border-radius: 4px; /* Rounded hover effect */
}
"""
        self.tabs.setStyleSheet(tab_stylesheet)
        self.tabs.setStyleSheet("""
    QTabBar::tab {
        background: #444;
        color: white;
        padding: 8px;
        border: 1px solid #222;
        border-radius: 4px;
        margin: 2px;
    }
    QTabBar::tab:selected {
        background: #555;
    }
    QTabBar::close-button {
        subcontrol-position: right;
        margin: 0px;
    }
""")

        self.setCentralWidget(self.tabs)

        self.tabBar = QTabBar()
        self.tabBar.setTabsClosable(True)
        self.createTab()

        layout = QHBoxLayout()
        navbar1 = QToolBar()
        self.setupUi(navbar1)
        navbar1.setStyleSheet("""
    QToolBar {
        background: #333;
        border: none;
        padding: 5px;
    }
    QToolButton {
        background: transparent;
        margin: 2px;
        padding: 5px;
        border-radius: 4px;
    }
    QToolButton:hover {
        background: #555;
    }
""")

        layout.addWidget(navbar1)

        navbarq = QToolBar()
        self.quit(navbarq)
        layout.addWidget(navbarq)

        navbar2 = QToolBar()
        self.setupBookmarksNavbar(navbar2)
        layout.addWidget(navbar2)
        navbar2.setStyleSheet("""
    QToolBar {
        background: #333;
        border: none;
        padding: 5px;
    }
    QToolButton {
        background: transparent;
        margin: 2px;
        padding: 5px;
        border-radius: 4px;
    }
    QToolButton:hover {
        background: #555;
    }
""")


        container = QWidget()
        container.setLayout(layout)
        self.addToolBar(navbar1)
        self.addToolBar(navbarq)
        self.addToolBar(navbar2)
        self.addToolBar(Qt.LeftToolBarArea, navbar2)

        
        self.urlBar = QLineEdit()
        self.urlBar.returnPressed.connect(self.navigateToUrl)
        navbar1.addWidget(self.urlBar)

        self.setWindowTitle("Disposable Units")

        self.setStyleSheet(qdarkstyle.load_stylesheet_pyqt5())
        self.show()


        # Timer 
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.onTimerTimeout)
        self.timer.start(6)  # 6sec

        self.timer_started = False  # A flag to prevent restarting the timer

    def onTimerTimeout(self):
        # Show the "Browser is Disposed" message
        QMessageBox.information(self, "Browser Disposed", "The browser session has been disposed due to inactivity for 10 minutes.")
        
        # Close the application
        self.quitApplication()

    def update_window_size(self):
        window_size = self.size()
        window_width = window_size.width()

        if hasattr(self, 'saved_window_size'):
            saved_width = self.saved_window_size
            if window_width != saved_width :
                self.saved_window_size = (window_width)
                window_width_s=int(modify_number(window_width))
                self.urlBar.setFixedWidth(window_width_s)
        else:
            self.saved_window_size = (window_width)

    def navigateBack(self):
        currentTab = self.tabs.currentWidget()
        if currentTab and hasattr(currentTab, 'webView'):
            currentTab.webView.back()

    def navigateForward(self):
        currentTab = self.tabs.currentWidget()
        if currentTab and hasattr(currentTab, 'webView'):
            currentTab.webView.forward()

    def reloadPage(self):
        currentTab = self.tabs.currentWidget()
        if currentTab and hasattr(currentTab, 'webView'):
            currentTab.webView.reload()

    def createTab(self, url=None, tabName=None, tabIndex=None):
        browserTab = TabWidget(url)
        index = self.tabs.insertTab(tabIndex if tabIndex is not None else self.tabs.count(
        ), browserTab, tabName if tabName else "Destroyer")

        closeButton = QPushButton("❌")
        closeButton.clicked.connect(
            lambda _, index=index: self.closeTab(index))
        self.tabBar.setTabButton(index, QTabBar.RightSide, closeButton)

        browserTab.urlChanged.connect(self.updateUrl)
        browserTab.webView.titleChanged.connect(
            lambda title, index=index: self.tabs.setTabText(index, title))

    def updateUrl(self, url):
        index = self.tabs.currentIndex()
        self.urlBar.setText(url.toString())
        self.tabs.setTabText(index, url.host())
        self.statusBar.showMessage(f'Page loaded: {url.toString()}')

    def navigate(self, url):
        currentWidget = self.tabs.currentWidget()
        if currentWidget and hasattr(currentWidget, 'webView'):
            Navigator.navigate(currentWidget.webView, url)

    def quit(self, navbar):
        quitAction = QAction('Quit', self)
        iconPath = "icons/exit.png"
        icon = QIcon(iconPath)
        quitAction.setIcon(icon)
        quitAction.triggered.connect(self.quitApplication)
        navbar.addActions([quitAction])

    def setupUi(self, navbar):
        backAction = QAction('Back', self)
        iconPath = "icons/Back.svg"
        icon = QIcon(iconPath)
        backAction.setIcon(icon)
        backAction.triggered.connect(self.navigateBack)

        forwardAction = QAction('Forward', self)
        iconPath = "icons/Forward.svg"
        icon = QIcon(iconPath)
        forwardAction.setIcon(icon)
        forwardAction.triggered.connect(self.navigateForward)

        reloadAction = QAction('Reload', self)
        iconPath = "icons/reload.svg"
        icon = QIcon(iconPath)
        reloadAction.setIcon(icon)
        reloadAction.triggered.connect(self.reloadPage)

        backAction.setToolTip("Go Back")
        forwardAction.setToolTip("Go Forward")
        reloadAction.setToolTip("Reload Page")
    # homeAction.setToolTip("Go to Homepage")


        homeIconPath = "icons/home.svg"
        homeIcon = QIcon(homeIconPath)
        homeAction = QAction('Home', self)
        homeAction.setIcon(homeIcon)
        homeAction.triggered.connect(self.navigateHome)

        navbar.addActions(
            [backAction, forwardAction, reloadAction, homeAction])

        newTabButton = QToolButton()
        newTabButton.setText(" ➕ ")
        iconPath = "icons/new_tab.svg"
        icon = QIcon(iconPath)
        newTabButton.setIcon(icon)
        newTabButton.clicked.connect(self.createTab)
        navbar.addWidget(newTabButton)

    def navigateHome(self):
        homeUrl = Urls.DEFAULT_HOME.value
        self.navigate(homeUrl)

    def closeTab(self, index):
        self.tabs.closeTab(index)

    def update_window_size(self):
        window_width = self.size().width()
        self.urlBar.setFixedWidth(int(window_width * 0.6))  # Set the URL bar to 60% of the window width


    def closeCurrentTab(self):
        index = self.tabs.currentIndex()
        self.closeTab(index)



    def quitApplication(self):
        appInstance = QtWidgets.QApplication.instance()
        if appInstance and self.isVisible():
            self.close()
        os.system('cls' if os.name == 'nt' else 'clear')

    def navigateToUrl(self):
        url = self.urlBar.text()
        currentTab = self.tabs.currentWidget()
        if currentTab:
            currentTab.webView.setUrl(QUrl(url))

    def setupBookmarksNavbar(self, navbar):
        bookmarks = [
            ('Shodan', Urls.SHODAN),
            ('DroneBL', Urls.DRONEBL),
            ('Dnsdumpster', Urls.DNSDUMPSTER),
            ('Dehashed', Urls.DEHASHED),
            ('Cybercrime', Urls.CYBERCRIME),
            ('Onyphe', Urls.ONYPHE),
            ('Ahmia', Urls.AHMIA),
            ('Archive', Urls.ARCHIVE),
            ('Arin', Urls.ARIN),
            ('Bgpview', Urls.BGPVIEW),
            ('Certificate', Urls.CERTIFICATE),
            ('Threat Crowd', Urls.THREAT_CROWD),
            ('VirusTotal', Urls.VIRUS_TOTAL),
            ('MIT OCW', Urls.MIT_OCW),
            ('HackerOne', Urls.HACKER_ONE),
            ('Cybrary', Urls.CYBRARY),
            ('OWASP Top 10', Urls.OWASP_TOP_10),
            ('Hacker News', Urls.HACKER_NEWS),
            ('Krebs Sec', Urls.KREBS_ON_SECURITY),
            ('TechCrunch', Urls.TECHCRUNCH),
            ('GitHub', Urls.GITHUB),
            ('Stack Overflow', Urls.STACK_OVERFLOW),
            ('Reddit Infosec', Urls.REDDIT_INFOSEC),
            ('Gutenberg', Urls.PROJECT_GUTENBERG),
            ('MetaX Rapid7', Urls.METAEXPLOIT_RAPID7),
            ('Hackertarget', Urls.HACKER_NMAP),
            ('ZDNet Security', Urls.ZDNET_SECURITY),
            ('SecurityWeek', Urls.SECURITY_WEEK),
            ('YCombinator', Urls.HACKER_NEWS_YCOMBINATOR),
            ('Dark Reading', Urls.DARK_READING),
            ('Whois Lookup', Urls.WHOIS_LOOKUP),
            ('URLVoid', Urls.URL_VOID),
            ('NIST NVD', Urls.NIST_NVD),
            ('Internet Archive', Urls.INTERNET_ARCHIVE),
            ('DNS Dumpster', Urls.DNS_DUMPSTER),
            ('Exploit DB', Urls.EXPLOIT_DB),
            ('Mitre ATT&CK', Urls.MITRE_ATTACK),
            ('OSVF', Urls.OSVF),
            ('Tenable', Urls.TENABLE),
            ('SANS Institute', Urls.SANS_INSTITUTE),
        ]

        for bookmarkText, bookmarkUrl in bookmarks:
            bookmarkAction = QAction(bookmarkText, self)
            bookmarkAction.triggered.connect(
                lambda _, url=bookmarkUrl: self.openBookmarkInNewTab(url.value))
            navbar.addAction(bookmarkAction)
    def openBookmarkInNewTab(self, url):
        currentTab = self.tabs.currentWidget()
        if currentTab:
            self.createTab(url)
            self.urlBar.setText(url)
            self.navigate(url)

    

def main():
    try:
        app = QApplication(sys.argv + ['--no-sandbox'])
        QApplication.setApplicationName("Destroyer Browser")
        window = AppMainWindow()

        font = app.font()
        font.setPointSize(12)  # Adjust the font size globally
        app.setFont(font)

        atexit.register(window.quitApplication)
        sys.exit(app.exec_())
    except Exception as e:
        print(e)


if __name__ == "__main__":
    main()

from PyQt5.QtNetwork import QNetworkProxy
from PyQt5.QtWebEngineWidgets import QWebEngineProfile

class AppMainWindow(QMainWindow):
    def __init__(self):
        super(AppMainWindow, self).__init__()

        # Set up a proxy
        self.set_proxy("192.168.0.100", 8080)  # Replace with your proxy IP and port

        # Existing initialization code...
        self.statusBar = self.statusBar()
        self.tabs = ClosableTabWidget()
        self.setCentralWidget(self.tabs)
        self.setWindowTitle("Disposable Units")
        self.setStyleSheet(qdarkstyle.load_stylesheet_pyqt5())
        self.show()
    
    def set_proxy(self, host, port):
        proxy = QNetworkProxy()
        proxy.setType(QNetworkProxy.HttpProxy)  # Options: HttpProxy, Socks5Proxy, etc.
        proxy.setHostName(host)
        proxy.setPort(port)
        QNetworkProxy.setApplicationProxy(proxy)

        # Optional: Configure the QWebEngine profile for the proxy
        profile = QWebEngineProfile.defaultProfile()
        profile.setHttpUserAgent("Mozilla/5.0 (X11; Linux x86_64) FakeBrowser/1.0")
        profile.setPersistentCookiesPolicy(QWebEngineProfile.NoPersistentCookies)

        print(f"Proxy set to {host}:{port}")
