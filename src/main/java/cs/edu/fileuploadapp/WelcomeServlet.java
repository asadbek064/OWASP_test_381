package cs.edu.fileuploadapp;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet("/")
public class WelcomeServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;

    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html");
        response.getWriter().println("<html><head></head><body>");
        response.getWriter().println("<form action=\"FileUploadServlet\" method=\"post\" enctype=\"multipart/form-data\">");
        response.getWriter().println("Select File to Upload:<input type=\"file\" name=\"fileName\"><br>");
        response.getWriter().println("<input type=\"submit\" value=\"Upload\">");
        response.getWriter().println("</form></body></html>");
    }
}
