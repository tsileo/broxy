/*
Package tview implements rich widgets for terminal based user interfaces. The
widgets provided with this package are useful for data exploration and data
entry.

Widgets

The package implements the following widgets:

  - TextView: Scrollable windows that display multi-colored text. Text may also
    be highlighted.
  - Table: Scrollable display of tabular data. Table cells, rows, or columns may
    also be highlighted.
  - List: A navigable text list with optional keyboard shortcuts.
  - InputField: One-line input fields to enter text.
  - DropDown: Drop-down selection fields.
  - Checkbox: Selectable checkbox for boolean values.
  - Button: Buttons which get activated when the user selects them.
  - Form: Forms composed of input fields, drop down selections, checkboxes, and
    buttons.
  - Modal: A centered window with a text message and one or more buttons.
  - Flex: A Flexbox based layout manager.
  - Pages: A page based layout manager.

The package also provides Application which is used to poll the event queue and
draw widgets on screen.

Hello World

The following is a very basic example showing a box with the title "Hello,
world!":

  package main

  import (
  	"github.com/rivo/tview"
  )

  func main() {
  	box := tview.NewBox().SetBorder(true).SetTitle("Hello, world!")
  	if err := tview.NewApplication().SetRoot(box, true).Run(); err != nil {
  		panic(err)
  	}
  }

First, we create a box primitive with a border and a title. Then we create an
application, set the box as its root primitive, and run the event loop. The
application exits when the application's Stop() function is called or when
Ctrl-C is pressed.

If we have a primitive which consumes key presses, we call the application's
SetFocus() function to redirect all key presses to that primitive. Most
primitives then offer ways to install handlers that allow you to react to any
actions performed on them.

More Demos

You will find more demos in the "demos" subdirectory. It also contains a
presentation (written using tview) which gives an overview of the different
widgets and how they can be used.

Colors

Throughout this package, colors are specified using the tcell.Color type.
Functions such as tcell.GetColor(), tcell.NewHexColor(), and tcell.NewRGBColor()
can be used to create colors from W3C color names or RGB values.

Almost all strings which are displayed can contain color tags. Color tags are
W3C color names or six hexadecimal digits following a hash tag, wrapped in
square brackets. Examples:

  This is a [red]warning[white]!
  The sky is [#8080ff]blue[#ffffff].

A color tag changes the color of the characters following that color tag. This
applies to almost everything from box titles, list text, form item labels, to
table cells. In a TextView, this functionality has to be switched on explicitly.
See the TextView documentation for more information.

In the rare event that you want to display a string such as "[red]" or
"[#00ff1a]" without applying its effect, you need to put an opening square
bracket before the closing square bracket. Examples:

  [red[]      will be output as [red]
  ["123"[]    will be output as ["123"]
  [#6aff00[[] will be output as [#6aff00[]

Styles

When primitives are instantiated, they are initialized with colors taken from
the global Styles variable. You may change this variable to adapt the look and
feel of the primitives to your preferred style.

Unicode Support

This package supports unicode characters including wide characters.

Type Hierarchy

All widgets listed above contain the Box type. All of Box's functions are
therefore available for all widgets, too.

All widgets also implement the Primitive interface. There is also the Focusable
interface which is used to override functions in subclassing types.

The tview package is based on https://github.com/gdamore/tcell. It uses types
and constants from that package (e.g. colors and keyboard values).

This package does not process mouse input (yet).
*/
package tview
