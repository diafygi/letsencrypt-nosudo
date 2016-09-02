import gi
gi.require_version('Gtk','3.0')
from gi.repository import Gtk, GLib
b = Gtk.Builder()
b.add_from_file("info.glade.xml")
info = {}
class UI:
	def __getattr__(self,name):
		val = b.get_object(name)
		setattr(self,name,val)
		return val
	def commit(self, button):
		prefixes = set()
		for prefix, in self.prefixes:
			prefixes.add(prefix)
		self.info['prefixes'] = tuple(prefixes)
		self.info['email'] = self.email.get_text()
		Gtk.main_quit()
	def get_info(self,domain, info):
		self.info = info
		self.domain.set_text(domain)
		if 'prefixes' in info:
			for prefix in info['prefixes']:
				self.prefixes.append([prefix])
		if 'email' in info:
			self.email.set_text(info['email'])
		self.top.show_all()
		Gtk.main()
		return self.info
	def hide(self,*a):
		ui.top.hide()
		Gtk.main_quit()

ui = UI()
# email, domain, prefixes, done
ui.top.connect('delete-event',ui.hide)
ui.done.connect('clicked',ui.commit)

import sys
sys.modules[__name__] = ui.get_info
