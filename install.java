    package org.cysecurity.cspf.jvl.controller;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Template
 * and open the template in the editor.
 */

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;
import java.util.UUID;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.cysecurity.cspf.jvl.model.HashMe;

/**
 *
 * @author breakthesec
 */
public class Install extends HttpServlet {

    private static final Set<String> ALLOWED_JDBC_DRIVERS = new HashSet<>(Arrays.asList(
        "com.mysql.jdbc.Driver",
        "com.mysql.cj.jdbc.Driver",
        "org.postgresql.Driver",
        "oracle.jdbc.OracleDriver",
        "com.microsoft.sqlserver.jdbc.SQLServerDriver"
    ));


    /**
     * Processes requests for HTTP <code>POST</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */

    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        // CWE-346: Add HSTS header to enforce HTTPS and prevent protocol downgrade
        response.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");

        // CWE-352: Validate CSRF token before processing any state-changing operation
        HttpSession session = request.getSession(false);
        String sessionToken = (session != null) ? (String) session.getAttribute("csrfToken") : null;
        String requestToken = request.getParameter("csrfToken");
        if (sessionToken == null || !sessionToken.equals(requestToken)) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid or missing CSRF token");
            return;
        }

        String configPath=getServletContext().getRealPath("/WEB-INF/config.properties");

        //Getting Database Configuration from User Input
        String dburl = request.getParameter("dburl");
        String jdbcdriver = request.getParameter("jdbcdriver");
        String dbuser = request.getParameter("dbuser");
        String dbpass = request.getParameter("dbpass");
        String dbname = request.getParameter("dbname");
        String siteTitle= request.getParameter("siteTitle");
        String adminuser= request.getParameter("adminuser");
        String adminpass= HashMe.hashMe(request.getParameter("adminpass"));

        // CWE-470: Validate jdbcdriver against an allowlist before Class.forName()
        if (jdbcdriver == null || !ALLOWED_JDBC_DRIVERS.contains(jdbcdriver)) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid JDBC driver specified");
            return;
        }

        // CWE-918: Validate dburl to prevent SSRF and Connection String Injection
        if (dburl == null || !isAllowedDbUrl(dburl)) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid database URL");
            return;
        }

        // CWE-89: Validate dbname with strict alphanumeric pattern before use in DDL
        if (dbname == null || !dbname.matches("^[a-zA-Z0-9_]+$")) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid database name");
            return;
        }

        //Moifying Configuration Properties:
         Properties config=new Properties();
         config.load(new FileInputStream(configPath));
         config.setProperty("dburl",dburl);
         config.setProperty("jdbcdriver",jdbcdriver);
         config.setProperty("dbuser",dbuser);
         config.setProperty("dbpass",dbpass);
         config.setProperty("dbname",dbname);
         config.setProperty("siteTitle",siteTitle);
         FileOutputStream fileout = new FileOutputStream(configPath);
         config.store(fileout, null);
         fileout.close();

        String i=request.getParameter("setup");
        response.setContentType("text/html;charset=UTF-8");
         try {
            PrintWriter out = response.getWriter();
            /* TODO output your page here. You may use following sample code. */
            out.println("<!DOCTYPE html>");
            out.println("<html>");
            out.println("<head>");
            out.println("<title>Servlet install</title>");
            out.println("</head>");
            out.println("<body>");
            if(setup(i, dburl, dbname, dbuser, dbpass, jdbcdriver, adminuser, adminpass))
            {
                out.print("successfully installed");
            }
            else
            {
                out.print("Something went wrong. Unable to install");
            }
            out.println("</body>");
            out.println("</html>");
        }
         catch(Exception e)
         {

         }
    }

    /**
     * Validates that the database URL targets only permitted local hosts.
     * Prevents SSRF and Connection String Injection (CWE-918).
     */
    private boolean isAllowedDbUrl(String url) {
        return url.startsWith("jdbc:mysql://localhost") ||
               url.startsWith("jdbc:mysql://127.0.0.1") ||
               url.startsWith("jdbc:postgresql://localhost") ||
               url.startsWith("jdbc:postgresql://127.0.0.1") ||
               url.startsWith("jdbc:sqlserver://localhost") ||
               url.startsWith("jdbc:oracle:thin:@localhost");
    }

     private boolean setup(String i, String dburl, String dbname, String dbuser, String dbpass, String jdbcdriver, String adminuser, String adminpass) throws IOException
    {
       // Defense-in-depth: re-validate all tainted inputs at the sink boundary (CWE-89, CWE-918, CWE-99)
       if (dbname == null || !dbname.matches("^[a-zA-Z0-9_]+$")) return false;
       if (dburl == null || !isAllowedDbUrl(dburl)) return false;
       if (jdbcdriver == null || !ALLOWED_JDBC_DRIVERS.contains(jdbcdriver)) return false;

       if(i.equals("1"))
       {

                    try
                   {
                    Class.forName(jdbcdriver);
                    Connection con= DriverManager.getConnection(dburl,dbuser,dbpass);
                      if(con!=null && !con.isClosed())
                        {
                             Statement stmt = con.createStatement();
                             stmt.executeUpdate("DROP DATABASE IF EXISTS "+dbname);

                             stmt.executeUpdate("CREATE DATABASE "+dbname);
                             con.close();
                            con= DriverManager.getConnection(dburl+dbname,dbuser,dbpass);
                             stmt = con.createStatement();
                              if(!con.isClosed())
                            {
                                //User Table creation
                                stmt.executeUpdate("Create table users(ID int NOT NULL AUTO_INCREMENT, username varchar(30),email varchar(60), password varchar(60), about varchar(50),privilege varchar(20),avatar TEXT,secretquestion int,secret varchar(30),primary key (id))");

                                // CWE-89: Use PreparedStatement for user-supplied admin credentials
                                PreparedStatement adminPs = con.prepareStatement(
                                    "INSERT into users(username, password, email, About, avatar, privilege, secretquestion, secret) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
                                adminPs.setString(1, adminuser);
                                adminPs.setString(2, adminpass);
                                adminPs.setString(3, "admin@localhost");
                                adminPs.setString(4, "I am the admin of this application");
                                adminPs.setString(5, "default.jpg");
                                adminPs.setString(6, "admin");
                                adminPs.setInt(7, 1);
                                adminPs.setString(8, "rocky");
                                adminPs.executeUpdate();
                                adminPs.close();

                                  stmt.executeUpdate("INSERT into users(username, password, email,About,avatar, privilege,secretquestion,secret) values ('victim','victim','victim@localhost','I am the victim of this application','default.jpg','user',1,'max')");
                                  stmt.executeUpdate("INSERT into users(username, password, email,About,avatar, privilege,secretquestion,secret) values ('attacker','attacker','attacker@localhost','I am the attacker of this application','default.jpg','user',1,'bella')");
                                stmt.executeUpdate("INSERT into users(username, password, email,About,avatar, privilege,secretquestion,secret) values ('NEO','trinity','neo@matrix','I am the NEO','default.jpg','user',1,'sentinel')");
                                stmt.executeUpdate("INSERT into users(username, password, email,About,avatar, privilege,secretquestion,secret) values ('trinity','NEO','trinity@matrix','it is Trinity','default.jpg','user',1,'sentinel')");
                                 stmt.executeUpdate("INSERT into users(username, password, email,About,avatar, privilege,secretquestion,secret) values ('Anderson','java','anderson@1999','I am computer programmer','default.jpg','user',1,'C++')");

                                  //Posts table creation
                                  stmt.executeUpdate("create table posts(postid int NOT NULL AUTO_INCREMENT, content TEXT,title varchar(100), user varchar(30), primary key (postid))");
                               stmt.executeUpdate("INSERT into posts(content,title, user) values ('Feel free to ask any questions about Java Vulnerable Lab','First Post', 'admin')");
                               stmt.executeUpdate("INSERT into posts(content,title, user) values ('Hello Guys, this is victim','Second Post', 'victim')");
                               stmt.executeUpdate("INSERT into posts(content,title, user) values ('Hello This is attacker','Third Post', 'attacker')");
                               stmt.executeUpdate("INSERT into posts(content,title, user) values ('Trinity! Help!','Help','neo')");


                               stmt.executeUpdate("create table tdata(id int, page varchar(30))");
                               stmt.executeUpdate("Insert into tdata values(1,'ext1.html')");
                                stmt.executeUpdate("Insert into tdata values(2,'ext2.html')");

                                //Messages Table Creation
                                stmt.executeUpdate("Create table Messages(msgid int NOT NULL AUTO_INCREMENT,name varchar(30),email varchar(60), msg varchar(500),primary key (msgid))");
                                stmt.executeUpdate("INSERT into Messages(name,email, msg) values ('TestUser','Test@localhost', 'Hi admin, how are you')");

                                //User Messages Table Creation recipient, sender, email, msg
                                stmt.executeUpdate("Create table UserMessages(msgid int NOT NULL AUTO_INCREMENT,recipient varchar(30),sender varchar(30),subject varchar(60), msg varchar(500),primary key (msgid))");
                                 stmt.executeUpdate("INSERT into UserMessages(recipient, sender, subject, msg) values ('attacker','admin','Hi','Hi<br/> This is admin of this page. <br/> Welcome to Our Forum')");
                                 stmt.executeUpdate("INSERT into UserMessages(recipient, sender, subject, msg) values ('victim','admin','Hi','Hi<br/> This is admin of this page. <br/> Welcome to Our Forum')");


                                 //Credit Card Table Creation
                                stmt.executeUpdate("Create table cards(id int,cardno varchar(80), cvv varchar(6),expirydate varchar(15))");
                                stmt.executeUpdate("INSERT into cards(id,cardno, cvv,expirydate) values ('1','4000123456789010','123','12/2014')");
                                stmt.executeUpdate("INSERT into cards(id,cardno, cvv,expirydate) values ('2','4111111111111111 ','321','7/2015')");
                                stmt.executeUpdate("INSERT into cards(id,cardno, cvv,expirydate) values ('3','5111111111111118','111','1/2017')");

                                //Files List Table Creation
                                stmt.executeUpdate("Create table FilesList(fileid int NOT NULL AUTO_INCREMENT,path text,primary key (fileid))");
                                stmt.executeUpdate("INSERT into FilesList(path) values ('/docs/doc1.pdf')");
                                 stmt.executeUpdate("INSERT into FilesList(path) values ('/docs/exampledoc.pdf')");

                                return true;
                            }
                              return false;
                        }
                   }
                   catch(SQLException ex)
                   {
                      System.out.println("SQLException: " + ex.getMessage());
                     System.out.println("SQLState: " + ex.getSQLState());
                     System.out.println("VendorError: " + ex.getErrorCode());
                   }
                   catch(ClassNotFoundException ex)
                   {
                       System.out.print("JDBC Driver Missing:<br/>"+ex);
                   }

       }
        return false;
    }

    // <editor-fold defaultstate="collapsed" desc="HttpServlet methods. Click on the + sign on the left to edit the code.">
    /**
     * Handles the HTTP <code>GET</code> method — generates a CSRF token and renders the install form.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // CWE-384: Invalidate any existing session to prevent session fixation, then issue a new one
        HttpSession oldSession = request.getSession(false);
        if (oldSession != null) {
            oldSession.invalidate();
        }
        // CWE-352: Generate CSRF token on GET and store in fresh session for POST validation
        HttpSession session = request.getSession(true);
        String csrfToken = UUID.randomUUID().toString();
        session.setAttribute("csrfToken", csrfToken);

        response.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
        response.setContentType("text/html;charset=UTF-8");
        PrintWriter out = response.getWriter();
        out.println("<!DOCTYPE html><html><head><title>Install</title></head><body>");
        out.println("<form method='post' action=''>");
        out.println("<input type='hidden' name='csrfToken' value='" + csrfToken + "'/>");
        out.println("<!-- TODO: Add installation form fields here -->");
        out.println("<input type='submit' value='Install'/>");
        out.println("</form></body></html>");
    }

    /**
     * Handles the HTTP <code>POST</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    /**
     * Returns a short description of the servlet.
     *
     * @return a String containing servlet description
     */
    @Override
    public String getServletInfo() {
        return "Short description";
    }// </editor-fold>

}
