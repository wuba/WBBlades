LibXL is a library for direct reading and writing Excel files.

Package contents:

  doc              C++ documentation
  examples/c       C examples (type 'make' in terminal window to build them)
  examples/c++     C++ examples (type 'make' in terminal window to build them)
  examples/qt      Qt project
  examples/xcode   XCode project (Cocoa)
  include_c        headers for C
  include_cpp      headers for C++
  lib/libxl.dylib  universal dynamic library (i386; x86_64)
  LibXL.framework  framework for using with XCode
  changelog.txt    change log
  license.txt      end-user license agreement
  readme.txt       this file

Using libxl.dylib in command line:

  g++ <your_cpp_file> -I<path_to_headers> -L<path_to_library> -lxl

Using LibXL.framework in Xcode project for MacOSX platform:

  - From the File menu, select "Add Files to ..."
  - Navigate to the folder "LibXL.framework" and click "Add" button
  - Click on target and go to "Build Phases" tab

    XCode 5:
  - Go to menu "Editor" > "Add Build Phase" and choose "Add Copy Files Build Phase"  
  
    XCode 4:
  - Click on "Add Build Phase" button and choose "Add Copy Files" from pop-up menu

  - Drag LibXL.framework from Project Navigator tree to "Copy Files" section
  - Switch the Destination drop-down list to "Frameworks"
  - Add the line #include "LibXL/libxl.h" to your source file
  - Project is ready for using LibXL functions

Documentation:

  http://www.libxl.com/xcode.html
  http://www.libxl.com/doc

Contact:

  support@libxl.com

