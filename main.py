
from gi.repository import Gtk, Gdk
import subprocess
import sys

class mainWindow(Gtk.Window):
	
	#Function Init
	
	def __init__(self):
		
		Gtk.Window.__init__(self)
		
		self.set_title("Volatility Frontend")
		self.set_size_request(700, 500)
		self.set_icon_from_file('university2.svg')
		self.set_position(Gtk.WindowPosition.CENTER)
		
		grid = Gtk.Grid()
		#self.add(grid)
		
		notebook = Gtk.Notebook()
		notebook.set_tab_pos(Gtk.PositionType.TOP)
		
		self.newMenu(grid)
		
		self.show_all()

	def simpleAnalysisOption(self, widget, grid, pageSections, option):
		
		textView = Gtk.TextView()
		command = Gtk.Entry()
		command.set_hexpand(True)
		
		if(option == "Command Line"):
		
			pageSections.destroy()
			
			self.newTextBoxCommand(pageSections, command, textView)
		
			if(grid.get_child_at(0, 1) == None):
				grid.attach(pageSections, 0, 1, 1, 1)
		
		elif(option == "Wizard"):
			
			pageSections.destroy()
			
			self.newImageProfileBar(pageSections, command, textView)
			
			if(grid.get_child_at(0, 1) == None):
				grid.attach(pageSections, 0, 1, 1, 1)
		
		pageSections.show_all()


	def newMenu(self, grid):
		
		pageSections = Gtk.Grid()
		grid_menu = Gtk.Grid()
		
		buttonBox = Gtk.ButtonBox()
		
		analysisButton = Gtk.MenuButton("Analysis")
		reportsButton = Gtk.Button("Reports")
		helpButton = Gtk.MenuButton("Help")
		
		buttonBox.add(analysisButton)
		buttonBox.add(reportsButton)
		buttonBox.add(helpButton)
		
		# Simple Analysis Menu
		
		menuAnalysis = Gtk.Menu()
		analysisButton.set_popup(menuAnalysis)
		
		simpleAnalysis = Gtk.MenuItem("Simple Analysis")
		menuAnalysis.append(simpleAnalysis)
		
		# Simple Analysis Submenu
		
		simpleAnalysisMenu = Gtk.Menu()
		simpleAnalysis.set_submenu(simpleAnalysisMenu)
		
		commandOption = Gtk.MenuItem("Command Line")
		simpleAnalysisMenu.append(commandOption)
		commandOption.connect("activate", self.simpleAnalysisOption, grid, pageSections, "Command Line")
		
		wizardOption = Gtk.MenuItem("Wizard")
		simpleAnalysisMenu.append(wizardOption)
		wizardOption.connect("activate", self.simpleAnalysisOption, grid, pageSections, "Wizard")
		
		wizardOption.show()
		commandOption.show()
		
		# Complete Analysis Menu
		
		completeAnalysis = Gtk.MenuItem("Complete Analysis")
		menuAnalysis.append(completeAnalysis)
		
		# Custom Analysis Menu
		
		customAnalysis = Gtk.MenuItem("Custom Analysis")
		menuAnalysis.append(customAnalysis)
		
		#buttonBox
		self.add(buttonBox)
		
		instructions = Gtk.Label("\n\n\n" + "Label" + "\n\n\n")

		simpleAnalysis.show()
		completeAnalysis.show()
		customAnalysis.show()
		
		# Help Menu Context
		
		menuHelp = Gtk.Menu()
		helpButton.set_popup(menuHelp)
		
		applicationHelp = Gtk.MenuItem("Volatility Frontend Help")
		menuHelp.append(applicationHelp)
		
		helpAbout = Gtk.MenuItem("About Volatility Frontend")
		menuHelp.append(helpAbout)
		
		applicationHelp.show()
		helpAbout.show()
		
		grid.add(grid_menu)


	def callbackEnter(self, widget, gridcommand, command, textView):
		
		entry = Gtk.Entry()
		entry.set_hexpand(True)
		entry.set_text(">>> ")
		
		parsedCommand = command.get_text().split()
		
		topCommandProcess =  "   Offset(V)" + "\t" + "  Name" + "\t" + "\t" + "PID" + "\t" + "      PPID" + "\t" + "Thds" + "   Hnds" + "  Sess" + " Wow64" + "\t" + "    Start" + "\t" + "\t" + "   Exit" +"\n" + "--------------------" + " " + "--------------------" + " " + "-----------------" + " " + "---------" + " " + "----------" + " " + "---------" + " " + "-------" + " " + "------------" + " " + "-----------------" + " " + "-----------------------------"
		
		charRedirectIndex = -1
		charPipeIndex = -1
		
		for string in parsedCommand:
			if (string == '>'):
				charRedirectIndex = parsedCommand.index(string)
			elif(string == '|'):
				charPipeIndex = parsedCommand.index(string)
		
		if parsedCommand[charRedirectIndex] == '>':
			
			fileNameIndex = charRedirectIndex + 1
			fileName = parsedCommand[fileNameIndex]
			f = open(fileName, 'w')
			pipe1 = subprocess.Popen(parsedCommand, stdout=f, shell=False)
			pipe1.wait()
			f.flush()
			return pipe1
		
		elif parsedCommand[charPipeIndex] == '|':
			
			pipeCommand = parsedCommand[charPipeIndex+1:]
			pipe1 = subprocess.Popen(parsedCommand, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
			pipe2 = subprocess.Popen(pipeCommand, stdin = pipe1.stdout, stdout = subprocess.PIPE)
			out = pipe2.communicate()[0]
			
			final = topCommandProcess + "\n" + out
			buffer = textView.get_buffer()
			
			buffer.set_text(final)
			return
		
		elif "volshell" in parsedCommand:
			
			pipe1 = subprocess.Popen(parsedCommand, stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE)

			gridcommand.attach(entry, 0, 5, 3, 1)
			option = " "
			
			while option != "exit()":
				
				line = pipe1.stderr.readline()
				
				buffer = textView.get_buffer()
				
				if line != '':
					
					a = []
					a.append(line.rstrip())
					tmp = "".join(a)
					option = tmp
					print option
				else:
					break
			
			entry.show()
			command = entry.connect("activate", self.shellCommand, entry, a, pipe1, textView)
		
		else:

			pipe1 = subprocess.Popen(parsedCommand, stdout = subprocess.PIPE)
			out = pipe1.communicate()[0]
			buffer = textView.get_buffer()
			buffer.set_text(out)
			return
	
	
	def shellCommand(self, widget, entry, err, pipe1, textView):
		
		command = entry.get_text().split()
		
		if command[0] == '>>>':
			parsedCommandShell = command[1:]
			print parsedCommandShell
			pipe = subprocess.Popen(["volshell", "hh()"], stdin = pipe1, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
			out = pipe.communicate("hh()")[0]
			
		else:
			pipe = subprocess.Popen(command, stdin = subprocess.PIPE, stdout = pipe, stderr = subprocess.PIPE)
			out, err = pipe.communicate()
			print command
		
		buffer = textView.get_buffer()
		buffer.set_text(err)
		
		return out
	
	
	def resetcommand(self, widget, command):
		command.set_text("python vol.py --profile=WinXPSP2x86 -f <file_image> <plugin> <plugin_option>")
	
	def selectedProfile(self, profileList, command):
		
		text = profileList.get_active_iter()
		
		if text != None:
			profile = profileList.get_model()[text][0]
	
	def selectedPlugin(self, pluginList, command):
		
		text = pluginList.get_active_iter()
		
		if text != None:
			
			plugin = pluginList.get_model()[text][0]
	
	def openMemoryFile(self, widget, command):
		
		fileName = None
		
		dialog = Gtk.FileChooserDialog("Open..", None, Gtk.FileChooserAction.OPEN, ("Open", Gtk.ResponseType.ACCEPT, "Cancel", Gtk.ResponseType.CANCEL))
		
		fileFilterAll = Gtk.FileFilter()
		fileFilterAll.set_name("All Memory Image Formats")
		fileFilterAll.add_pattern("*.vmem")
		fileFilterAll.add_pattern("*.img")
		fileFilterAll.add_pattern("*.raw")
		fileFilterAll.add_pattern("*.iso")
		fileFilterAll.add_pattern("*.lime")
		fileFilterAll.add_pattern("*.dump")
		fileFilterAll.add_pattern("*.vmss")
		fileFilterAll.add_pattern("*.vmsn")
		fileFilterAll.add_pattern("*.sys")
		fileFilterAll.add_pattern("*.elf")
		fileFilterAll.add_pattern("*.E01")
		fileFilterAll.add_pattern("*.dmp")
		fileFilterAll.add_pattern("*.macho")
		fileFilterAll.add_pattern("*.hpak")

		fileFilterVmem = Gtk.FileFilter()
		fileFilterVmem.set_name("Virtual Machine Paging File (*.vmem)")
		fileFilterVmem.add_pattern("*.vmem")
		
		fileFilterImg = Gtk.FileFilter()
		fileFilterImg.set_name("Image Data File (*.img)")
		fileFilterImg.add_pattern("*.img")

		fileFilterRaw = Gtk.FileFilter()
		fileFilterRaw.set_name("Raw Image File (*.raw)")
		fileFilterRaw.add_pattern("*.raw")
		
		fileFilterIso = Gtk.FileFilter()
		fileFilterIso.set_name("CD Disk Image File (*.iso)")
		fileFilterIso.add_pattern("*.iso")
		
		fileFilterLime = Gtk.FileFilter()
		fileFilterLime.set_name("Linux/Android Dump File (*.lime)")
		fileFilterLime.add_pattern("*.lime")
		
		fileFilterDump = Gtk.FileFilter()
		fileFilterDump.set_name("Microsoft Crash Dump / Android Lime Dump File (*.dump; *.dmp)")
		fileFilterDump.add_pattern("*.dump")
		fileFilterDump.add_pattern("*.dmp")
		
		fileFilterVMware = Gtk.FileFilter()
		fileFilterVMware.set_name("VMware Snapshot / VMware Saved State File (*.vmss; *.vmsn)")
		fileFilterVMware.add_pattern("*.vmss")
		fileFilterVMware.add_pattern("*.vmsn")
		
		fileFilterSys = Gtk.FileFilter()
		fileFilterSys.set_name("Windows Hibernation File (*.sys)")
		fileFilterSys.add_pattern("*.sys")
		
		fileFilterElf = Gtk.FileFilter()
		fileFilterElf.set_name("VirtualBox Core Dump ELF64 File (*.elf)")
		fileFilterElf.add_pattern("*.elf")
		
		fileFilterEwf = Gtk.FileFilter()
		fileFilterEwf.set_name("Expert Witness File v1(*.E01)")
		fileFilterEwf.add_pattern("*.E01")
		
		fileFilterMacho = Gtk.FileFilter()
		fileFilterMacho.set_name("Machintosh Memory Reader File (*.macho)")
		fileFilterMacho.add_pattern("*.macho")
		
		fileFilterHpak = Gtk.FileFilter()
		fileFilterHpak.set_name("Fast Dump Pro File (*.hpak)")
		fileFilterHpak.add_pattern("*.hpak")
		
		dialog.add_filter(fileFilterAll)
		dialog.add_filter(fileFilterVmem)
		dialog.add_filter(fileFilterImg)
		dialog.add_filter(fileFilterRaw)
		dialog.add_filter(fileFilterIso)
		dialog.add_filter(fileFilterLime)
		dialog.add_filter(fileFilterDump)
		dialog.add_filter(fileFilterVMware)
		dialog.add_filter(fileFilterSys)
		dialog.add_filter(fileFilterElf)
		dialog.add_filter(fileFilterEwf)
		dialog.add_filter(fileFilterMacho)
		dialog.add_filter(fileFilterHpak)
		
		response = dialog.run()
		
		if response == Gtk.ResponseType.ACCEPT:
			fileName = dialog.get_filename()
			currentCommand = command.get_text()
			parsedCommand = currentCommand.replace("<file_image>", fileName)
			command.set_text(parsedCommand)
		elif response == Gtk.ResponseType.CANCEL:
			dialog.destroy()
		dialog.destroy()
	
	
	def newImageProfileBar(self, pageSections, command, textView):
		
		#FileChooser for Memory File
		selectedFile = Gtk.Button("Select Memory File")
		imageLabel = Gtk.Label("Memory Image File:  ")
		
		selectedFile.connect("clicked", self.openMemoryFile, command)
		
		#ComboBox for Profile Selection
		profileLabel = Gtk.Label("  Profile:  ")
		pluginLabel = Gtk.Label("  Plugin:  ")
		
		imageProfileGrid = Gtk.Grid()
		
		profile = []
		tempProfile = ""
		profileFile = open('profiles.txt', 'r')
		profile = profileFile.readlines()
		tempProfile = "".join(profile)
		profile = tempProfile.split()
		
		listProfiles = Gtk.ListStore(str)
		
		for item in profile:
			listProfiles.append([item])
		
		profileList = Gtk.ComboBox.new_with_model(listProfiles)
		profileList.set_active(24) #Default Profile Index
		profileList.connect("changed", self.selectedProfile, command)
		
		#ComboBox for Plugin Selection
		
		plugin = []
		tempPlugin = ""
		pluginFile = open('plugins.txt', 'r')
		plugin = pluginFile.readlines()
		tempPlugin = "".join(plugin)
		plugin = tempPlugin.split()
		
		listPlugins = Gtk.ListStore(str)
		
		for itemP in plugin:
			listPlugins.append([itemP])
		
		pluginList = Gtk.ComboBox.new_with_model(listPlugins)
		pluginList.set_active(0) #Default Plugin Index
		pluginList.connect("changed", self.selectedPlugin, command)
		
		cellrenderertext = Gtk.CellRendererText()
		profileList.pack_start(cellrenderertext, True)
		profileList.add_attribute(cellrenderertext, "text", 0)
		
		cellrenderertextP = Gtk.CellRendererText()
		pluginList.pack_start(cellrenderertextP, True)
		pluginList.add_attribute(cellrenderertextP, "text", 0)
		
		textView.set_editable(False)
		textView.set_cursor_visible(False)
		
		searchWizardButton = Gtk.Button("Start")
		outputLabel = Gtk.Label("Output:")
		
		scrollTextView = Gtk.ScrolledWindow()
		scrollTextView.add(textView)
		
		scrollTextView.set_hexpand(True)
		scrollTextView.set_vexpand(True)
		
		#Add items to grid
		imageProfileGrid.add(imageLabel)
		imageProfileGrid.add(selectedFile)
		imageProfileGrid.add(profileLabel)
		imageProfileGrid.add(profileList)
		imageProfileGrid.add(pluginLabel)
		imageProfileGrid.add(pluginList)
		imageProfileGrid.add(searchWizardButton)
		imageProfileGrid.attach(outputLabel, 0, 1, 1, 1)
		imageProfileGrid.attach(scrollTextView, 0, 2, 7, 1)
		pageSections.attach(imageProfileGrid, 0, 0, 1, 1)
	
	
	def newTextBoxCommand(self, pageSections, command, textView):
		
		gridcommand = Gtk.Grid()
		
		command.connect("activate", self.callbackEnter, gridcommand, command, textView)
		
		textView.set_editable(False)
		textView.set_cursor_visible(False)
		
		scrollTextView = Gtk.ScrolledWindow()
		scrollTextView.add(textView)
		
		scrollTextView.set_hexpand(True)
		scrollTextView.set_vexpand(True)
		
		label = Gtk.Label("Command:  ")
		command.set_text("python vol.py --profile=WinXPSP2x86 -f <file_image> <plugin> <plugin_option>")
		botaoReset = Gtk.Button("Reset")
		botaoReset.connect("clicked", self.resetcommand, command)
		
		outputLabel = Gtk.Label("Output:")
		
		gridcommand.add(label)
		gridcommand.add(command)
		gridcommand.add(botaoReset)
		gridcommand.attach(outputLabel, 0, 3, 1, 1)
		gridcommand.attach(scrollTextView,0, 4, 3, 1)
		pageSections.attach(gridcommand, 0, 2, 2, 1)
	

win = mainWindow()
win.connect("delete-event", Gtk.main_quit)
win.show_all()
Gtk.main()
