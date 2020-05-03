import wx 
import wx.lib.scrolledpanel
import tracing
import os
import prctl
from time import sleep


frames = []

prctl.set_child_subreaper(1)
class MainWindow(wx.Frame):
    def __init__(self, parent, title):
        wx.Frame.__init__(self, parent, title=title, size=(500,250))
        #hSizer = wx.BoxSizer(wx.HORIZONTAL)
        vSizer = wx.BoxSizer(wx.VERTICAL)
        #vSizer.AddStretchSpacer(1)
        hSizer = wx.BoxSizer(wx.HORIZONTAL)

        filemenu = wx.Menu()

        menuAbout = filemenu.Append(wx.ID_ABOUT, "&About", "Information about the program")
        filemenu.AppendSeparator()
        menuExit = filemenu.Append(wx.ID_EXIT,"E&xit", "Exit the program")

        menuBar = wx.MenuBar()
        menuBar.Append(filemenu,"&File")
        self.SetMenuBar(menuBar)

        

        #panel= wx.Panel(self)
        #self.quote = wx.StaticText(panel, label="Your quote: ", pos=(20, 30))
        self.userChoiceDropDown = wx.ComboBox(self, wx.ID_ANY, "Pick one", choices = ["Root", "Specified User"], size=(200, -1))
        self.userChoiceText = wx.TextCtrl(self, wx.ID_ANY, "User name here", size=(200, -1))
        hSizer.Add(self.userChoiceDropDown, 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.TOP | wx.BOTTOM, 20)
        hSizer.Add(self.userChoiceText, 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.TOP | wx.BOTTOM, 20)
        loadWithMethodsButton = wx.Button(self, wx.ID_ANY, "Run Program\n(already compiled with -gpubnames)")
        loadNoMethodsButton = wx.Button(self, wx.ID_ANY, "Run Program (no -gpubnames)")
        loadTracingFile = wx.Button(self, wx.ID_ANY, "Load tracing file")
        #grid.Add(loadWithMethodsButton, pos = (3,3))
        #vSizer.Add(loadWithMethodsButton, 0, wx.ALIGN_CENTER_HORIZONTAL)
        #vSizer.Add(self.userChoiceDropDown, 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.TOP | wx.BOTTOM, 20)
        vSizer.Add(hSizer,0, wx.ALL, 5)
        vSizer.Add(loadWithMethodsButton, 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.TOP | wx.BOTTOM, 20)
        #vSizer.AddStretchSpacer(1)
        #vSizer.Add(loadNoMethodsButton, 0, wx.ALIGN_CENTER_HORIZONTAL)
        vSizer.Add(loadNoMethodsButton, 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.TOP | wx.BOTTOM, 20)
        #vSizer.AddStretchSpacer(1)
        #vSizer.Add(loadTracingFile, 0, wx.ALIGN_CENTER_HORIZONTAL)
        vSizer.Add(loadTracingFile, 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.TOP | wx.BOTTOM, 20)
        #vSizer.AddStretchSpacer(1)

        self.Bind(wx.EVT_MENU, self.OnAbout, menuAbout)
        self.Bind(wx.EVT_MENU, self.OnExit, menuExit)

        self.Bind(wx.EVT_COMBOBOX, self.userChoice, self.userChoiceDropDown)
        self.Bind(wx.EVT_BUTTON, self.loadWithMethods, loadWithMethodsButton)
        self.Bind(wx.EVT_BUTTON, self.loadFile, loadTracingFile)

        #hSizer.Add(grid, 0, wx.ALL, 5)
        #vSizer.Add(hSizer, 0, wx.ALL, 5)
        vSizer.SetSizeHints(self)
        self.SetSizer(vSizer)

        self.Show(True)
        #tracing.main()

    def OnAbout(self, event):
        dlg = wx.MessageDialog(self, "Tool for tracing methods and system calls of C and C++ programs.\nDeveloped by Cameron Turner, 2020", "About Program")

        dlg.ShowModal()
        dlg.Destroy()

    def OnExit(self, event):
        self.Close(True)

    def userChoice(self, event):
        print(self.userChoiceDropDown.GetValue())
    
    def loadFile(self):
        self.dirname = ""
        #dlg = wx.FileDialog(self, "Choose a file", self.dirname, "", "*.trc", wx.FD_OPEN)
        dlg = wx.FileDialog(self, "Choose a file", self.dirname, "", "*", wx.FD_OPEN)
        if dlg.ShowModal() == wx.ID_OK:
            self.filename = dlg.GetFilename()
            self.dirname = dlg.GetDirectory()
            location = os.path.join(self.dirname, self.filename)
            f = open(location, 'r')
            #self.control.SetValue(f.read())
            f.close()
        #dlg.destroy()
        return location
    
    def loadWithMethods(self, event):
        

        #check for if user is running by root or given user
        print(self.userChoiceDropDown.GetValue())
        choice = self.userChoiceDropDown.GetValue()
        if(choice == "Pick one"):
            wx.MessageBox("Please pick if user running program is root or otherwise")
        elif(choice == "Specified User"):
            print(self.userChoiceText.GetValue())
            choice = self.userChoiceText.GetValue()
            #grab the user name
            #set choice to the given name

        #presuming root otherwise, don't change choice


        program_path = self.loadFile()
        #print(program_path)
        #ask for executable

        #run tracing, pass in program name and location
        output = tracing.main(program_path, choice)
        if(output == -1):
            print("An error has occurred")
            wx.MessageBox("An error has occurred. Please check console for more detail")
        else:
            tracing_data = output[0]
            parent_pid = output[1]
            children = output[2]
            #print(output)
            frames.append(SubWindow(frame, str(parent_pid)+" Tracing Output", tracing_data[parent_pid]))
            for i in children:
                frames.append(SubWindow(frame, str(i)+" Tracing Output", tracing_data[i]))
            #receive tracing file and file of children
            #pass subset of the dictionary to each window
    
    def loadNoMethods(self, event):
        dlg = wx.MessageDialog(self, "Load no methods", "About Program")

        dlg.ShowModal()
        dlg.Destroy()

    #def spawnWindows(self, event, data)


class SubWindow(wx.Frame):
    def __init__(self, parent, title, output):
        wx.Frame.__init__(self, parent, title=title, size=(500,250))
        #print(trace_target)
        screenSize = wx.DisplaySize()
        screenWidth = screenSize[0]
        screenHeight = screenSize[1]
        vSizer1 = wx.BoxSizer(wx.VERTICAL)
        vSizer2 = wx.BoxSizer(wx.VERTICAL)

        hSizer = wx.BoxSizer(wx.HORIZONTAL)
        panel = wx.lib.scrolledpanel.ScrolledPanel(self,-1, size=(screenWidth,400), pos=(0,28), style=wx.SIMPLE_BORDER)
        panel.SetupScrolling()

        sysButtons = []
        methodButtons = []
        j = 0

        for i in output[1]:
            #string = "Syscall: " + str(i[3]) + "\nStart time: " + str(i[0]) + "\nDuration: " + str(i[1]) + "\nretval: " + str(i[4])
            try:
                string = "Syscall: " + str(i[3]) + "\nStart time: " + str(i[0]) + "\nDuration: " + str(i[1]) + "\nretval: " + str(i[4])
            except IndexError: 
                string = "Syscall: " + str(i[3]) + "\nStart time: " + str(i[0]) + "\nDuration: " + str(i[1]) + "\nNo return value"
            sysButtons.append(wx.Button(panel, wx.ID_ANY, string))
            vSizer1.Add(sysButtons[j], 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.TOP | wx.BOTTOM, 20)
            j = j + 1
        
        j = 0
        for i in output[0]:
            try:
                string = "Method: " + str(i[3]) + "\nStart time: " + str(i[0]) + "\nDuration: " + str(i[1]) + "\nretval: " + str(i[4])
            except IndexError:
                string = "Method: " + str(i[3]) + "\nStart time: " + str(i[0]) + "\nDuration: " + str(i[1]) + "\nNo return value "
            #methodButtons.append(wx.Button(self, wx.ID_ANY, string))
            methodButtons.append(wx.Button(panel, wx.ID_ANY, string))
            vSizer2.Add(methodButtons[j], 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.TOP | wx.BOTTOM, 20)
            j = j + 1
        """Button1 = wx.Button(self, wx.ID_ANY, "But1")
        Button2 = wx.Button(self, wx.ID_ANY, "But2")
        Button3 = wx.Button(self, wx.ID_ANY, "But3")
        Button4 = wx.Button(self, wx.ID_ANY, "But4")"""

        """vSizer1.Add(Button1, 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.TOP | wx.BOTTOM, 20)
        vSizer1.Add(Button2, 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.TOP | wx.BOTTOM, 20)
        hSizer.Add(vSizer1, 0, wx.ALL | wx.EXPAND, 5)
        vSizer2.Add(Button3, 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.TOP | wx.BOTTOM, 20)
        vSizer2.Add(Button4, 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.TOP | wx.BOTTOM, 20)
        hSizer.Add(vSizer2, 0, wx.ALL| wx.EXPAND, 5)"""
        hSizer.Add(vSizer1, 0, wx.ALL | wx.EXPAND, 5)
        hSizer.Add(vSizer2, 0, wx.ALL| wx.EXPAND, 5)
        panel.SetSizer(hSizer)
        #self.FitInside()
        #self.SetScrollRate(5, 5)

        trace_data = output
        print(trace_data)
        self.Show(True)


app=wx.App(False)
frame = MainWindow(None, "Tracing")
frame.Show(True)
app.MainLoop()
