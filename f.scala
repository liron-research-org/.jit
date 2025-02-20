package controllers

import play.api.mvc._
import javax.inject._
import java.sql.{Connection, ResultSet, DriverManager}

@Singleton
class HomeController @Inject()(val controllerComponents: ControllerComponents) extends BaseController{

  def twoAction() = Action { implicit request: Request[AnyContent] =>
    val bodyVals = request.body.asFormUrlEncoded
    val name = bodyVals.get("username").head
    // ruleid: tainted-sql-from-http-request
    val sql = "SELECT * FROM table WHERE name = " + name + ";"
    val conn = DriverManager.getConnection("jdbc:mysql://localhost:8080", "guest", "password")
    val stmt = conn.createStatement()
    val rs = stmt.execute(sql)
    Ok(rs.first())
  }

  def threeAction() = Action { implicit request: Request[AnyContent] =>
    val bodyVals = request.body.asFormUrlEncoded
    val name = bodyVals.get("username").head
    val conn = DriverManager.getConnection("jdbc:mysql://localhost:8080", "guest", "password")
    val stmt = conn.createStatement()
    // ruleid: tainted-sql-from-http-request
    val rs = stmt.execute(s"SELECT * FROM table WHERE name = $name;")
    Ok(rs.first())
  }

  def okAction1() = Action { implicit request: Request[AnyContent] =>
    val name = "hardcoded_value"
    val conn = DriverManager.getConnection("jdbc:mysql://localhost:8080", "guest", "password")
    val stmt = conn.createStatement()
    // ok: tainted-sql-from-http-request
    val rs = stmt.execute(s"SELECT * FROM table WHERE name = $name;")
    Ok(rs.first())
  }

  def okAction2(name: String) = Action { implicit request: Request[AnyContent] =>
    val name = "value"
    // ok: tainted-sql-from-http-request
    val sql = "SELECT * FROM table WHERE name = " + name + ";"
    val conn = DriverManager.getConnection("jdbc:mysql://localhost:8080", "guest", "password")
    val stmt = conn.createStatement()
    val rs = stmt.execute(sql)
    Ok(rs.first())
  }

}

class Test {
  def bad1(value:String) = Action {
    if (!Files.exists(Paths.get("public/lists/" + value))) {
      NotFound("File not found")
    } else {
      // ruleid: path-traversal-fromfile
      val result = Source.fromFile("public/lists/" + value).getLines().mkString // Weak point
      Ok(result)
    }
  }


  def bad3(value:String) = Action {
    if (!Files.exists(Paths.get("public/lists/" + value))) {
      NotFound("File not found")
    } else {
      // ruleid: path-traversal-fromfile
      val result = Source.fromFile("%s/%s".format("public/lists", value)).getLines().mkString // Weak point
      Ok(result)
    }
  }

  def bad4(value:String) = Action {
    if (!Files.exists(Paths.get("public/lists/" + value))) {
      NotFound("File not found")
    } else {
      var filename1 = "public/lists/"
      val filename = filename1.concat(value)
      // ruleid: path-traversal-fromfile
      val result = Source.fromFile(filename).getLines().mkString // Weak point
      Ok(result)
    }
  }

  def ok(value:String) = Action {
    val filename = "public/lists/" + FilenameUtils.getName(value)

    if (!Files.exists(Paths.get(filename))) {
      NotFound("File not found")
    } else {
      // ok: path-traversal-fromfile
      val result = Source.fromFile(filename).getLines().mkString // Fix
      Ok(result)
    }
  }
}
