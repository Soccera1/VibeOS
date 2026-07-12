#include <X11/Xlib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    Display *display = XOpenDisplay(NULL);
    if (display == NULL) {
        fputs("xhello: cannot open display\n", stderr);
        return 1;
    }
    if (argc > 1 && strcmp(argv[1], "--probe") == 0) {
        printf("X11 connection established: vendor=%s screens=%d\n",
               ServerVendor(display), ScreenCount(display));
        XCloseDisplay(display);
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--pointer") == 0) {
        Window root = DefaultRootWindow(display);
        Window root_return, child_return;
        int root_x, root_y, win_x, win_y;
        unsigned int mask;

        sleep(5);
        if (!XQueryPointer(display, root, &root_return, &child_return,
                           &root_x, &root_y, &win_x, &win_y, &mask)) {
            fputs("xhello: pointer is not on the default screen\n", stderr);
            XCloseDisplay(display);
            return 1;
        }
        printf("pointer: x=%d y=%d buttons=0x%x\n", root_x, root_y, mask);
        XCloseDisplay(display);
        return 0;
    }

    int screen = DefaultScreen(display);
    Window root = RootWindow(display, screen);
    Window window = XCreateSimpleWindow(display, root, 80, 80, 520, 180, 2,
                                        BlackPixel(display, screen), WhitePixel(display, screen));
    XStoreName(display, window, "VibeOS X11");
    XSelectInput(display, window, ExposureMask | KeyPressMask | ButtonPressMask | StructureNotifyMask);
    XMapWindow(display, window);

    const char *message = "XLibre is running on VibeOS - press any key to exit";
    for (;;) {
        XEvent event;
        XNextEvent(display, &event);
        if (event.type == Expose) {
            XDrawString(display, window, DefaultGC(display, screen), 24, 90,
                        message, (int)strlen(message));
        } else if (event.type == KeyPress || event.type == ButtonPress || event.type == DestroyNotify) {
            break;
        }
    }

    XDestroyWindow(display, window);
    XCloseDisplay(display);
    return 0;
}
