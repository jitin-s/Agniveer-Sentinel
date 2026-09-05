import java.io.*;
import java.sql.*;
import java.net.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import javax.servlet.http.*;

public class VajraCommandCenter extends HttpServlet {

    private static final String DB_URL = "jdbc:sqlite:vajra.db";
    private static final String DB_USER = "admin";
    private static final String DB_PASSWORD = "Army@2026";

    private static final String API_TOKEN =
        "INDIA-VAJRA-SECRET-2026";

    public void doGet(
        HttpServletRequest request,
        HttpServletResponse response
    ) throws IOException {

        String action = request.getParameter("action");

        if ("personnel".equals(action)) {
            searchPersonnel(request, response);
        }
        else if ("report".equals(action)) {
            downloadReport(request, response);
        }
        else if ("system".equals(action)) {
            systemInfo(response);
        }
        else if ("fetch".equals(action)) {
            fetchRemoteData(request, response);
        }
        else {
            response.getWriter().println(
                "VAJRA COMMAND CENTER"
            );
        }
    }

    private void searchPersonnel(
        HttpServletRequest request,
        HttpServletResponse response
    ) throws IOException {

        String name = request.getParameter("name");

        try {
            Connection connection =
                DriverManager.getConnection(
                    DB_URL,
                    DB_USER,
                    DB_PASSWORD
                );

            Statement statement =
                connection.createStatement();

            String query =
                "SELECT * FROM personnel WHERE name LIKE '%"
                + name
                + "%'";

            ResultSet result =
                statement.executeQuery(query);

            while (result.next()) {

                response.getWriter().println(
                    result.getString("name")
                    + " | "
                    + result.getString("rank")
                    + " | "
                    + result.getString("unit")
                );
            }

            connection.close();

        } catch (Exception e) {

            response.getWriter().println(
                e.getMessage()
            );
        }
    }

    private void downloadReport(
        HttpServletRequest request,
        HttpServletResponse response
    ) throws IOException {

        String filename =
            request.getParameter("file");

        File file =
            new File("reports", filename);

        try {
            FileInputStream in = new FileInputStream(file);
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                response.getOutputStream().write(buffer, 0, bytesRead);
            }
            in.close();
        } catch (Exception e) {
            response.getWriter().println(e.getMessage());
        }
    }

    private void systemInfo(
        HttpServletResponse response
    ) throws IOException {

        response.getWriter().println(
            "VAJRA SYSTEM STATUS: ONLINE"
        );
    }

    private void fetchRemoteData(
        HttpServletRequest request,
        HttpServletResponse response
    ) throws IOException {

        String targetUrl =
            request.getParameter("url");

        try {
            URL url = new URL(targetUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                response.getWriter().println(line);
            }
            reader.close();
        } catch (Exception e) {
            response.getWriter().println(e.getMessage());
        }
    }
}
