#!/usr/bin/python3
import gettext
import os
import getpass
import pprint
import threading
import time
import copy
import hashlib
import codecs

import gi
gi.require_version('Gtk', '3.0')
gi.require_version('Gdk', '3.0')
from gi.repository import Gdk, Gtk, GLib

import certification
import subprocess

from pwd import getpwnam

gettext.install("gooroom-client-server-register", "/usr/share/gooroom/locale")

class RegisterThread(threading.Thread):
    def __init__(self, datas, application):
        threading.Thread.__init__(self)
        self.datas = datas
        self.application = application
        self.WORK_DIR = '/usr/lib/gooroom/gooroomClientServerRegister'

    def make_result_view(self, result, errlog=None):
        result_image = self.application.builder.get_object('result_image')
        result_title = self.application.builder.get_object('result_title')
        result_detail = self.application.builder.get_object('result_detail')
        result_button = self.application.builder.get_object('result_button')

        result_detail.set_justify(Gtk.Justification.CENTER)
        text_mark = str("<span fgcolor='#0251ff'>%s</span>" % _('Administrator'))

        if result:
            result_button.get_style_context().remove_class('mono_button')
            result_button.get_style_context().add_class('accent_button')
            result_button.set_label(_('Finished'))
            result_button.connect('clicked', Gtk.main_quit)

            result_image.set_from_file(self.WORK_DIR + '/images/image-success.svg')
            result_title.set_text(_('Client registration completed.'))

            text_orig = str(_('Contact to Server Administrator for Detail Management.'))
            text_chage = text_orig.replace(_('Administrator'), text_mark)
            result_detail.set_markup(text_chage)
        else:
            result_button.get_style_context().add_class('mono_button')
            result_button.set_label(_('Prev'))
            result_button.connect('clicked', self.application.prev_page)

            result_image.set_from_file(self.WORK_DIR + '/images/image-failed.svg')
            result_title.set_text(_('Client registration failed.'))
            if errlog:
                text_orig = str('{0}\n{1}'.format(errlog, _('Contact to Server Administrator for Resolution.')))
            else:
                text_orig = str(_('Contact to Server Administrator for Resolution.'))
            text_chage = text_orig.replace(_('Administrator'), text_mark)
            result_detail.set_markup(text_chage)

        #register_stack = self.application.builder.get_object('register_stack')
        #register_stack.set_visible_child_name('result_page')
        register_stack = self.application.builder.get_object('stack1')
        register_stack.set_visible_child_name('page1')

    def result_format(self, result):
        "Return result log pretty"
        result_text = ''
        for text in result:
            result_text += pprint.pformat(text) + '\n'

        return result_text

    def run(self):
        errlog = str()
        try:
            textbuffer = self.application.builder.get_object('textbuffer_result')
            client_data = next(self.datas)
            server_certification = self.application.server_certification
            sc = server_certification.certificate(client_data)
            for server_result in sc:
                result_text = self.result_format(server_result['log'])
                current_text = textbuffer.get_text(textbuffer.get_start_iter(),
                    textbuffer.get_end_iter(),
                    True)

                Gdk.threads_enter()
                textbuffer.set_text('{0}\n{1}'.format(current_text, result_text))
                Gdk.threads_leave()

                if server_result['err']:
                    raise Exception

            server_data = next(self.datas)
            client_certification = certification.ClientCertification(client_data['domain'])
            cc = client_certification.certificate(server_data)
            for client_result in cc:
                result_text = self.result_format(client_result['log'])
                current_text = textbuffer.get_text(textbuffer.get_start_iter(),
                    textbuffer.get_end_iter(),
                    True)

                Gdk.threads_enter()
                textbuffer.set_text('{0}\n{1}'.format(current_text, result_text))
                Gdk.threads_leave()
                if client_result['err']:
                    errlog = str(client_result['log'][-2])
                    raise Exception
        except Exception as e:
            GLib.idle_add(self.make_result_view, False, errlog)
            print(type(e), e)
        else:
            GLib.idle_add(self.make_result_view, True)

class Registering():
    "Registering parent class"
    def __init__(self):
        self.WORK_DIR = '/usr/lib/gooroom/gooroomClientServerRegister'

    def result_format(self, result):
        "Return result log pretty"
        # TODO: formatting more pretty
        result_text = ''
        for text in result:
            result_text += pprint.pformat(text) + '\n'

        return result_text

    def make_hash_cn(self):
        cmd = subprocess.run(['/usr/sbin/dmidecode', '-s', 'system-serial-number'], stdout=subprocess.PIPE, universal_newlines=True)
        result = cmd.stdout.rstrip() + '/'
        cmd = subprocess.run(['/usr/sbin/dmidecode', '-s', 'system-uuid'], stdout=subprocess.PIPE, universal_newlines=True)
        result += cmd.stdout.rstrip() + '/'
        cmd = subprocess.run(['/usr/sbin/dmidecode', '-s', 'baseboard-serial-number'], stdout=subprocess.PIPE, universal_newlines=True)
        result += cmd.stdout.rstrip()
        hash_result = hashlib.md5(result.encode()).hexdigest()
        base64_result = codecs.encode(codecs.decode(hash_result, 'hex'), 'base64').decode().rstrip()
        return base64_result

    def make_mac(self):
        """
        make cn with sn + mac
        """

        ENP_PATH = '/sys/class/net/enp0s3/address'
        if os.path.exists(ENP_PATH):
            with open(ENP_PATH) as f:
                cn = f.read().strip('\n').replace(':', '')
                print('enp0s3={}'.format(cn))
                return cn
        else:
            import glob
            ifaces = [i for i in glob.glob('/sys/class/net/*')]
            ifaces.sort()
            for iface in ifaces:
                if iface == '/sys/class/net/lo':
                    continue
                with open(iface+'/address') as f2:
                    cn = f2.read().strip('\n').replace(':', '')
                    print('iface={}'.format(cn))
                    return cn
            return 'CN-NOT-FOUND-ERROR'

    def make_cn(self):

        CN_PATH = '/etc/gooroom/gooroom-client-server-register/gcsr.conf'
        if os.path.exists(CN_PATH):
            try:
                import configparser
                parser = configparser.RawConfigParser()
                parser.optionxform = str
                parser.read(CN_PATH)
                cn = parser.get('certificate', 'client_name').strip().strip('\n')
                print('gcsr.conf={}'.format(cn))
                return cn
            except:
                pass

        cn = self.make_mac()
        return cn + self.make_hash_cn()

    def make_ipname(self):
        """
        make name with IP
        """
        return os.popen('hostname --all-ip-addresses').read().split(' ')[0]

    def make_ipv6name(self):
        """
        make name with IPv6
        """
        return os.popen('/sbin/ip -6 addr | grep inet6 | awk -F \'[ \t]+|/\' \'{print $3}\' | grep -v ^::1').read().split('\n')[0]

class GUIRegistering(Registering):
    def __init__(self):
        Registering.__init__(self)
        Gdk.threads_init()

        self.WORK_DIR = '/usr/lib/gooroom/gooroomClientServerRegister'
        cssProvider = Gtk.CssProvider()
        cssProvider.load_from_path ('%s/style.scss'% self.WORK_DIR)
        screen = Gdk.Screen.get_default()
        styleContext = Gtk.StyleContext()
        styleContext.add_provider_for_screen (screen, cssProvider, Gtk.STYLE_PROVIDER_PRIORITY_USER)

        glade_file = "%s/gooroomClientServerRegister.glade" % self.WORK_DIR
        self.builder = Gtk.Builder()
        self.builder.add_from_file(glade_file)

        self.window = self.builder.get_object('window1')
        self.window.set_default_size(500, 500)
        self.window.set_title(_('Gooroom Client Server Register'))
        self.window.set_icon_name('gooroom-client-server-register')
        self.window.set_position(Gtk.WindowPosition.CENTER)

        self.accel_group = Gtk.AccelGroup()
        key, mod = Gtk.accelerator_parse("F1")
        self.accel_group.connect(key, mod, Gtk.AccelFlags.VISIBLE, self.open_help)
        self.window.add_accel_group(self.accel_group)

        self.builder.connect_signals(self)
        self.builder.get_object('label1').set_text(_('Terminal Registration'))
        self.builder.get_object('label2').set_text(_('Authenticate the terminal and use the terminal conveniently.\n'\
                                                     'If you proceed with the registration process of the terminal,\n'\
                                                     'it helps the administrator in charge to control the terminal\n'\
                                                     'application, security, and browser infringement.'))
        self.builder.get_object('label3').set_text(_('Registration Key'))
        self.builder.get_object('label4').set_text(_('GKM Server Address'))
        self.builder.get_object('button1').set_label(_('Register'))
        self.builder.get_object('button1').connect('clicked', self.onRegisterPressed)
        dg1 = self.builder.get_object('regkey_MD')
        dg1.add_buttons(Gtk.STOCK_OK, Gtk.ResponseType.OK)
        dg2 = self.builder.get_object('server_MD')
        dg2.add_buttons(Gtk.STOCK_OK, Gtk.ResponseType.OK)
        self.builder.get_object('regkey_info').connect('clicked', self.onRegkeyClick)
        self.builder.get_object('server_info').connect('clicked', self.onServerClick)
        self.builder.get_object('entry_regkey1').set_placeholder_text(_('Enter the registration key'))
        self.builder.get_object('entry_serveraddr').set_placeholder_text(_('Enter the server address'))
        self.builder.get_object('entry_serverip').set_placeholder_text(_('Enter the server ip'))
        self.builder.get_object('button_prev1').connect('clicked', self.prev_page_easy)
        self.builder.get_object('button_ok1').connect('clicked', Gtk.main_quit)
        self.builder.get_object('button_close1').connect('clicked', Gtk.main_quit)

        self.builder.get_object('label_result').set_text(_('Result data'))
        self.server_certification = certification.ServerCertification()

        self.window.connect("delete-event", Gtk.main_quit)
        self.window.show_all()
        Gdk.threads_enter()
        Gtk.main()
        Gdk.threads_leave()

    def prev_page(self, button):
        self.builder.get_object('stack1').set_visible_child_name('page0')

    def onRegkeyClick(self, button):
        self.show_info_dialog(_('Enter the terminal registration key issued by the GPMS administrator'))
        return

    def onServerClick(self, button):
        self.show_info_dialog(_('Enter the domain and IP address of the GKM server'))
        return

    def open_help(self, key, mod, flag, widget):
        os.system("yelp help:gooroom-help-gcsr")

    def onRegisterPressed(self, button):
        textbuffer = self.builder.get_object('textbuffer_result')
        textbuffer.set_text('')

        current_page = self.builder.get_object('stack1').get_visible_child_name()

        if not self.builder.get_object('entry_serveraddr').get_text():
            self.show_info_dialog(_('Enter the server address'))
            return
        if not self.builder.get_object('entry_regkey1').get_text():
            self.show_info_dialog(_('Enter the registration key'))
            return

        gkm_domain = self.builder.get_object('entry_serveraddr').get_text()
        serverinfo = self.get_serverinfo()
        server_certification = self.server_certification
        server_certification.add_hosts_gkm(serverinfo)
        try:
            for ip_type in server_certification.get_root_certificate({'domain':gkm_domain, 'path':""}):
                self.ip_type=ip_type
        except:
            self.show_info_dialog(_('Check the server address'))
            return

        datas = self.easy_get_datas()
        register_thread = RegisterThread(datas, self)
        register_thread.start()

    def get_serverinfo(self):
        """
        get domain/ip of gkm for writing to /etc/hosts
        """

        hosts_data = {}
        if self.builder.get_object('entry_serverip').get_text():
            gkm_domain = self.builder.get_object('entry_serveraddr').get_text()
            gkm_ip = self.builder.get_object('entry_serverip').get_text()
            hosts_data['gkm'] = (gkm_domain,gkm_ip)

        return hosts_data

    def easy_get_datas(self):
        "Return input information. notebook page 0 and 1"
        server_data = {}
        server_data['domain'] = self.builder.get_object('entry_serveraddr').get_text()
        server_data['path'] = ''
        server_data['serverinfo'] = self.get_serverinfo()
        yield server_data

        client_data = {}
        client_data['cn'] = self.make_cn()
        client_data['name'] = ''
        client_data['ou'] = ''
        client_data['password_system_type'] = "sha256"
        client_data['user_id'] = ''
        client_data['user_pw'] = ''
        client_data['valid_date'] = ''
        client_data['comment'] = ''
        client_data['api_type'] = 'regkey'
        client_data['regkey'] = self.builder.get_object('entry_regkey1').get_text()
        client_data['cert_reg_type'] = '2'

        if self.ip_type == 'ipv4':
            client_data['ipv4'] = self.make_ipname()
            client_data['ipv6'] = ''
        else:
            client_data['ipv4'] = ''
            client_data['ipv6'] = self.make_ipv6name()
        yield client_data

    def prev_page_easy(self, button):
        current_page = self.builder.get_object('stack1').get_visible_child_name()
        if current_page == 'page1':
            current_page = 'page0'

        self.builder.get_object('stack1').set_visible_child_name(current_page)

    def catch_user_id(self):
        """
        get session login id
        (-) not login
        (+user) local user
        (user) remote user
        """

        pp = subprocess.Popen(
            ['loginctl', 'list-sessions'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)

        pp_out, pp_err = pp.communicate()
        pp_out = pp_out.decode('utf8').split('\n')

        for l in pp_out:
            l = l.split()
            if len(l) < 3:
                continue
            try:
                sn = l[0].strip()
                if not sn.isdigit():
                    continue
                uid = l[1].strip()
                if not uid.isdigit():
                    continue
                user = l[2].strip()
                pp2 = subprocess.Popen(
                    ['loginctl', 'show-session', sn],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE)

                pp2_out, pp2_err = pp2.communicate()
                pp2_out = pp2_out.decode('utf8').split('\n')
                service_lightdm = False
                state_active = False
                active_yes = False
                for l2 in pp2_out:
                    l2 = l2.split('=')
                    if len(l2) != 2:
                        continue
                    k, v = l2
                    k = k.strip()
                    v = v.strip()
                    if k == 'Id'and v != sn:
                        break
                    elif k == 'User'and v != uid:
                        break
                    elif k == 'Name' and v != user:
                        break
                    elif k == 'Service':
                        if v == 'lightdm':
                            service_lightdm = True
                        else:
                            break
                    elif k == 'State':
                        if v == 'active':
                            state_active = True
                        else:
                            break
                    elif k == 'Active':
                        if v == 'yes':
                            active_yes = True

                    if service_lightdm and state_active and active_yes:
                        gecos = getpwnam(user).pw_gecos.split(',')
                        if len(gecos) >= 5 and gecos[4] == 'gooroom-account':
                            return user
                        else:
                            return '+{}'.format(user)
            except:
                AgentLog.get_logger().debug(agent_format_exc())

        return '-'

    def file_browse(self, button):
        '''
        dialog = Gtk.FileChooserDialog(_('Select a certificate'), self.builder.get_object('window1'),
            Gtk.FileChooserAction.OPEN,
            (Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
             Gtk.STOCK_OPEN, Gtk.ResponseType.OK))

        self.add_filters(dialog)

        response = dialog.run()
        if response == Gtk.ResponseType.OK:
            self.builder.get_object('entry_file').set_text(dialog.get_filename())

        dialog.destroy()
        '''

        login_id = self.catch_user_id()
        if login_id[0] == '+':
            login_id = login_id[1:]
        fp = subprocess.check_output(
            ['sudo', 
            '-u', 
            login_id, 
            '/usr/lib/gooroom/gooroomClientServerRegister/file-chooser.py'])
        fp = fp.decode('utf8').strip()
        if fp and fp.startswith('path='):
            self.builder.get_object('entry_file').set_text(fp[5:])

    def show_info_dialog(self, message, error=None):
        dialog = Gtk.MessageDialog(self.builder.get_object('window1'), 0,
            Gtk.MessageType.INFO, Gtk.ButtonsType.OK, 'info dialog')
        dialog.format_secondary_text(message)
        dialog.set_icon_name('gooroom-client-server-register')
        dialog.props.text = error
        response = dialog.run()
        if response == Gtk.ResponseType.OK or response == Gtk.ResponseType.CLOSE:
            dialog.destroy()


class ShellRegistering(Registering):

    def __init__(self):
        Registering.__init__(self)

    def input_surely(self, prompt):
        user_input = ''
        while not user_input:
            user_input = input(prompt)

        return user_input

    def cli(self):
        'Get request info from keyboard using cli'

        #SARABAL VERSION REQUEST
        client_data = {}
        while True:
            cert_reg_type = self.input_surely(_('Enter certificate registration type[0:create 1:update 2: create or update]: '))
            if cert_reg_type != '0' and cert_reg_type != '1' and cert_reg_type != '2':
                continue
            break
        client_data['cert_reg_type'] = cert_reg_type

        #client_data['cn'] = self.input_surely(_('Enter the Client ID: '))
        client_data['cn'] = self.make_cn()

        if cert_reg_type == '1':
            client_data['name'] = ''
            client_data['ou'] = ''
        else:
            client_ip = self.make_ipname()
            client_data['name'] = \
                input(_('Enter the client name')+'[{}]: '.format(client_ip)) or client_ip
            client_data['ou'] = ''

        api_type = 'regkey'
        client_data['regkey'] = self.input_surely(_('Enter the registration key: '))
        client_data['api_type'] = api_type

        client_data['password_system_type'] = "sha256"
        client_data['valid_date'] = input(_('(Option)Enter the valid date(YYYY-MM-DD): '))
        client_data['comment'] = input(_('(Option)Enter the comment: '))
        if self.ip_type == 'ipv4':
            client_data['ipv4'] = self.make_ipname()
            client_data['ipv6'] = ''
        else:
            client_data['ipv4'] = ''
            client_data['ipv6'] = self.make_ipv6name()
        return client_data

    def run(self, args):
        if args.cmd == 'cli':
            print(_('Gooroom Client Server Register.\n'))
            server_data = {}
            server_data['domain'] = self.input_surely(_('Enter the domain name: '))
            server_data['ip'] = self.input_surely(_('Enter the IP Address: '))
            server_data['serverinfo'] = {'gkm': (server_data['domain'], server_data['ip'])}

        elif args.cmd == 'noninteractive-regkey':
            server_data = {'domain':args.domain, 'path':args.CAfile, 'serverinfo':{'gkm': (args.domain, args.IP)}}

        server_certification = certification.ServerCertification()
        server_certification.add_hosts_gkm(server_data['serverinfo'])
        for ip_type in server_certification.get_root_certificate({'domain':server_data['domain'], 'path':""}):
            self.ip_type=ip_type

        self.do_certificate(args, server_certification, server_data)

    def do_certificate(self, args, server_certification, server_data):
        """
        certificate
        """

        sc = server_certification.certificate(server_data)
        for result in sc:
            result_text = self.result_format(result['log'])
            if result['err']:
                print("###########ERROR(%s)###########" % result['err'])
                print(result_text)
                exit(result['err'])

            print(result_text)

        if args.cmd == 'cli':
            client_data = self.cli()
        elif args.cmd == 'noninteractive':
            print ("args.comd: [ %s ]" %args.cmd)
            client_data = {}
            client_data['cn'] = self.make_cn()
            client_data['name'] = args.name
            client_data['ou'] = ''
            client_data['password_system_type'] = "sha256"
            client_data['user_id'] = args.id
            client_data['user_pw'] = args.password
            client_data['valid_date'] = args.expiration_date
            client_data['comment'] = args.comment
            client_data['api_type'] = 'id/pw'
            client_data['cert_reg_type'] = args.cert_reg_type
            if self.ip_type == 'ipv4':
                client_data['ipv4'] = self.make_ipname()
                client_data['ipv6'] = ''
            else:
                client_data['ipv4'] = ''
                client_data['ipv6'] = self.make_ipv6name()
        elif args.cmd == 'noninteractive-regkey':
            print ("args.comd: [ %s ]" %args.cmd)
            client_data = {}
            client_data['cn'] = self.make_cn()
            client_data['name'] = args.name
            client_data['ou'] = ''
            client_data['password_system_type'] = "sha256"
            client_data['valid_date'] = args.expiration_date
            client_data['comment'] = args.comment
            client_data['regkey'] = args.regkey
            client_data['api_type'] = 'regkey'
            client_data['cert_reg_type'] = args.cert_reg_type
            if self.ip_type == 'ipv4':
                client_data['ipv4'] = self.make_ipname()
                client_data['ipv6'] = ''
            else:
                client_data['ipv4'] = ''
                client_data['ipv6'] = self.make_ipv6name()
        else:
            print('can not support mode({})'.format(args.cmd))
            return

        client_certification = certification.ClientCertification(server_data['domain'])
        cc = client_certification.certificate(client_data)
        for result in cc:
            result_text = self.result_format(result['log'])
            if result['err']:
                print("###########ERROR(%s)###########" % result['err'])
                print(result_text)
                exit(1)

            print(result_text)

    def make_name(self):
        """
        make name with hostname@ip
        """

        import socket
        return socket.gethostname()
