import wx 
import tracing

class MainWindow(wx.Frame):
    def __init__(self, parent, title):
        wx.Frame.__init__(self, parent, title=title, size=(500,250))
        #hSizer = wx.BoxSizer(wx.HORIZONTAL)
        vSizer = wx.BoxSizer(wx.VERTICAL)
        vSizer.AddStretchSpacer(1)
        #grid = wx.GridBagSizer(hgap=5, vgap=5)


        filemenu = wx.Menu()

        menuAbout = filemenu.Append(wx.ID_ABOUT, "&About", "Information about the program")
        filemenu.AppendSeparator()
        menuExit = filemenu.Append(wx.ID_EXIT,"E&xit", "Exit the program")

        menuBar = wx.MenuBar()
        menuBar.Append(filemenu,"&File")
        self.SetMenuBar(menuBar)

        

        #panel= wx.Panel(self)
        #self.quote = wx.StaticText(panel, label="Your quote: ", pos=(20, 30))
        #lWMBlabel = "Run Program\n".center(5)+"(already compiled with -gpubnames)".center(5)
        loadWithMethodsButton = wx.Button(self, wx.ID_ANY, "Run Program\n(already compiled with -gpubnames)")
        loadNoMethodsButton = wx.Button(self, wx.ID_ANY, "Run Program (no -gpubnames)")
        loadTracingFile = wx.Button(self, wx.ID_ANY, "Load tracing file")
        #grid.Add(loadWithMethodsButton, pos = (3,3))
        vSizer.Add(loadWithMethodsButton, 0, wx.ALIGN_CENTER_HORIZONTAL)
        vSizer.AddStretchSpacer(1)
        vSizer.Add(loadNoMethodsButton, 0, wx.ALIGN_CENTER_HORIZONTAL)
        vSizer.AddStretchSpacer(1)
        vSizer.Add(loadTracingFile, 0, wx.ALIGN_CENTER_HORIZONTAL)
        vSizer.AddStretchSpacer(1)

        self.Bind(wx.EVT_MENU, self.OnAbout, menuAbout)
        self.Bind(wx.EVT_MENU, self.OnExit, menuExit)
        self.Bind(wx.EVT_BUTTON, self.loadWithMethods, loadWithMethodsButton)

        self.Bind(wx.EVT_BUTTON, self.loadFile, loadTracingFile)

        #hSizer.Add(grid, 0, wx.ALL, 5)
        #vSizer.Add(hSizer, 0, wx.ALL, 5)
        self.SetSizer(vSizer)

        self.Show(True)
        tracing.main()

    def OnAbout(self, event):
        dlg = wx.MessageDialog(self, "Tool for tracing methods and system calls of C and C++ programs.\nDeveloped by Cameron Turner, 2020", "About Program")

        dlg.ShowModal()
        dlg.Destroy()

    def OnExit(self, event):
        self.Close(True)
    
    def loadFile(self, event):
        self.dirname = ""
        dlg = wx.FileDialog(self, "Choose a file", self.dirname, "", "*.trc", wx.FD_OPEN)
        if dlg.ShowModal() == wx.ID_OK:
            self.filename = dlg.GetFilename()
            self.dirname = dlg.GetDirectory()
            f = open(os.path.join(self.dirname, self.filename), 'r')
            self.control.SetValue(f.read())
            f.close()
        dlg.destroy()
    
    def loadWithMethods(self, event):
        dlg = wx.MessageDialog(self, "Load with methods", "About Program")

        dlg.ShowModal()
        dlg.Destroy()

        #run tracing, pass in program name and location
        #receive tracing file
        #run method to spawn windows
    
    def loadNoMethods(self, event):
        dlg = wx.MessageDialog(self, "Load no methods", "About Program")

        dlg.ShowModal()
        dlg.Destroy()

    #def spawnWindows(self, event, data)


#class SubWindow(wx.Frame):
    #def __init__(self, parent, title):


app=wx.App(False)
frame = MainWindow(None, "Tracing")
frame.Show(True)
app.MainLoop()
