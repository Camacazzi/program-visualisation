import wx 
import wx.lib.scrolledpanel
import tracing
import os
import prctl
from time import sleep
import operator
import matplotlib
import matplotlib.pyplot as plt
from matplotlib.backends.backend_wxagg import FigureCanvasWxAgg as FigureCanvas
from matplotlib.figure import Figure
matplotlib.use('WXAgg')
plt.style.use('ggplot')


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
        self.Bind(wx.EVT_BUTTON, self.loadTraceFile, loadTracingFile)

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
            return
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

    def loadTraceFile(self, event):
        save_path = self.loadFile()
        print(save_path)
        output = tracing.load_data(save_path)
        print(output[0])
        print(output[1])
        print(output[2])

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



class SubWindow(wx.Frame):
    def __init__(self, parent, title, output):
        wx.Frame.__init__(self, parent, title=title, size=(500,250))        

        screenSize = wx.DisplaySize()
        screenWidth = screenSize[0]
        screenHeight = screenSize[1]

        self.mainVSizer = wx.BoxSizer(wx.VERTICAL)
        self.vSizerSyscall = wx.BoxSizer(wx.VERTICAL)
        self.vSizerMethod = wx.BoxSizer(wx.VERTICAL)

        self.hSizerDropDown = wx.BoxSizer(wx.HORIZONTAL)
        self.hSizerDetailed = wx.BoxSizer(wx.HORIZONTAL)
        self.hSizerTimeGraph = wx.BoxSizer(wx.HORIZONTAL)

        panel = wx.lib.scrolledpanel.ScrolledPanel(self,-1, size=(screenWidth,400), pos=(0,28), style=wx.SIMPLE_BORDER)
        panel.SetupScrolling()

        self.displayChoiceDropDown = wx.ComboBox(panel, wx.ID_ANY, "Default", choices = ["Detailed", "Syscall Execution Graph"], size=(200, -1))
        self.hSizerDropDown.Add(self.displayChoiceDropDown, 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.TOP | wx.BOTTOM, 20)
        self.Bind(wx.EVT_COMBOBOX, self.swapView, self.displayChoiceDropDown)

        self.syscall_text = wx.StaticText(panel, label="System Calls", pos = (20, 0))
        self.vSizerSyscall.Add(self.syscall_text, 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.TOP | wx.BOTTOM, 5)
        self.method_text = wx.StaticText(panel, label="User Methods", pos = (20, 0))
        self.vSizerMethod.Add(self.method_text, 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.TOP | wx.BOTTOM, 5)

        sysButtons = []
        methodButtons = []
        gauges = []
        

        stdioFound = 0
        buffer = 0
        try:
            f = open("/usr/include/stdio.h", 'r')
            stdioFound = 1
            for i in f:
                if(i[0:14] == "#define BUFSIZ"):
                    buffer = int(i[15:len(i)-1])
                    print(buffer)
        except:
            #stido.h not in there...
            print("stdio.h not in /usr/include")
            try:
                f = open("/usr/local/include/sdio.h", 'r')
                stdioFound = 1
                for i in f:
                    if(i[0:14] == "#define BUFSIZ"):
                        buffer = int(i[15:len(i)-1])
                        print(buffer)
            except:
                print("stdio.h not in /usr/local/include either...")
        
        if(buffer == 0):
            stdioFound = 0
            print("Didn't find buffer value")


        start = output[1][0][0]
        j = 0
        k = 0
        for i in output[1]:
            #string = "Syscall: " + str(i[3]) + "\nStart time: " + str(i[0]) + "\nDuration: " + str(i[1]) + "\nretval: " + str(i[4])
            try:
                string = "Syscall: " + str(i[3]) + "\nStart time: " + str(i[0]-start) + "\nDuration: " + str(i[1]) + "\nretval: " + str(i[4])
            except IndexError: 
                string = "Syscall: " + str(i[3]) + "\nStart time: " + str(i[0]-start) + "\nDuration: " + str(i[1]) + "\nNo return value"
            sysButtons.append(wx.Button(panel, wx.ID_ANY, string))
            
            
            self.vSizerSyscall.Add(sysButtons[j], 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.TOP | wx.BOTTOM, 20)
            if(stdioFound == 1 and str(i[3]) == "write"):
                #add wx.gauge here
                gauges.append(wx.Gauge(panel, range = buffer, size = (100, 25), style = wx.GA_HORIZONTAL))
                if(int(i[4]) < buffer/100):
                    gauges[k].SetValue(buffer/100 + 1)
                else:
                    gauges[k].SetValue(int(i[4]))
                
                self.vSizerSyscall.Add(gauges[k], 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.TOP | wx.BOTTOM, 5)
                k = k + 1
            j = j + 1
        
        j = 0
        for i in output[0]:
            try:
                string = "Method: " + str(i[3]) + "\nStart time: " + str(i[0]-start) + "\nDuration: " + str(i[1]) + "\nretval: " + str(i[4])
            except IndexError:
                string = "Method: " + str(i[3]) + "\nStart time: " + str(i[0]-start) + "\nDuration: " + str(i[1]) + "\nNo return value "
            #methodButtons.append(wx.Button(self, wx.ID_ANY, string))
            methodButtons.append(wx.Button(panel, wx.ID_ANY, string))
            self.vSizerMethod.Add(methodButtons[j], 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.TOP | wx.BOTTOM, 20)
            j = j + 1
        
        #collect bar graph info

        #WARNING: AWFUL CODE FOLLOWING!!!!!!
        """syscall_times = {}
        for i in output[1]:
            try:
                syscall_times[str(i[3])] = syscall_times[str(i[3])] + int(i[1])
            except:
                syscall_times[str(i[3])] = int(i[1])

        syscall_array = []
        j = 0
        for key, value in syscall_times.items():
            syscall_array.append((key, value))
        syscall_array.sort(key = operator.itemgetter(1), reverse=True)
        syscall_names = []
        syscall_values = []
        for i in syscall_array:
            syscall_names.append(i[0])
            syscall_values.append(i[1])"""
        syscall_times = {}
        for i in output[1]:
            try:
                syscall_times[str(i[3])][0] = syscall_times[str(i[3])][0] + int(i[1])
                syscall_times[str(i[3])][1] = syscall_times[str(i[3])][1] + 1
            except:
                syscall_times[str(i[3])] = [int(i[1]), 1]

        syscall_array = []
        j = 0
        for key, value in syscall_times.items():
            syscall_array.append((key, value))
        #syscall_array.sort(key = operator.itemgetter(1), reverse=True)
        syscall_array = sorted(syscall_array, key=lambda x: x[1][0], reverse=True)
        syscall_names = []
        syscall_values = []
        syscall_count = []
        for i in syscall_array:
            syscall_names.append(i[0])
            syscall_values.append(i[1][0])
            syscall_count.append(i[1][1])

        print(syscall_count)
        fig = plt.figure()

        ax = fig.add_subplot(111)

        ax.bar(syscall_names,syscall_values)
  
        ax.set_xticklabels(syscall_names, rotation = 45)
        for i,v in enumerate(syscall_values):
            ax.text(i, v + 1, syscall_count[i], color='blue')
        plt.yscale("log")

        canvas = FigureCanvas(panel, -1, fig)


        self.hSizerTimeGraph.Add(canvas, 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.TOP | wx.BOTTOM, 20)




        self.hSizerDetailed.Add(self.vSizerSyscall, 0, wx.ALL | wx.EXPAND, 5)
        self.hSizerDetailed.Add(self.vSizerMethod, 0, wx.ALL| wx.EXPAND, 5)
        

        self.mainVSizer.Add(self.hSizerDropDown, 0, wx.ALL| wx.EXPAND, 5)
        self.mainVSizer.Add(self.hSizerDetailed, 0, wx.ALL| wx.EXPAND, 5)
        self.mainVSizer.Add(self.hSizerTimeGraph, 0, wx.ALL| wx.EXPAND, 5)

        panel.SetSizer(self.mainVSizer)

        self.hSizerTimeGraph.Hide(self)
        self.hSizerTimeGraph.ShowItems(show=False)

        self.Show(True)
    
    def swapView(self, event):
        choice = self.displayChoiceDropDown.GetValue()
        if(choice == "Detailed"):
            self.hSizerTimeGraph.Hide(self)
            self.hSizerTimeGraph.ShowItems(show=False)
            self.hSizerDetailed.Show(self)
            self.hSizerDetailed.ShowItems(show=True)
            
        elif(choice == "Syscall Execution Graph"):
            self.hSizerDetailed.Hide(self)
            self.hSizerDetailed.ShowItems(show=False)
            self.hSizerTimeGraph.Show(self)
            self.hSizerTimeGraph.ShowItems(show=True)





app=wx.App(False)
frame = MainWindow(None, "Tracing")
frame.Show(True)
app.MainLoop()
