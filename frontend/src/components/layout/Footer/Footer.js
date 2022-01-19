import React from "react";
import playStore from "../../../images/playstore.png";
import appStore from "../../../images/Appstore.png";
import "./Footer.css";
import { AiOutlineInstagram, AiOutlineYoutube, AiOutlineFacebook } from 'react-icons/ai';
import Logo from "../../../images/logo.png";
import {Link} from "react-router-dom";

const Footer = () => {
  return (
    <footer id="footer">
      <div className="leftFooter">
        <img src={playStore} alt="playstore" />
        <img src={appStore} alt="Appstore" />
      </div>

      <div className="midFooter">
        <img src={Logo} alt="playstore"  width='150px'/>
        <p>High Quality is our First Priority</p>

        <p>Copyrights 2021 &copy; Khurram Shehzad Ahmad</p>
      </div>

      <div className="rightFooter">
        <Link><AiOutlineInstagram fontSize='30px'/></Link>
        <Link><AiOutlineYoutube fontSize='30px'/></Link>
        <Link><AiOutlineFacebook fontSize='30px'/></Link>
      </div>
    </footer>
  );
};

export default Footer;
