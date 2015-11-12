/*! 
@file CameraControlZeroG.cs
@author Zoe Hardisty. <www.zoehardistydesign.com>
		<https://github.com/zoebear/Radia/CameraControlZeroG.cs>
@date June 2015
@version 0.9.1

@section LICENSE

The MIT License (MIT)

Copyright (c) 2015 Zoe Hardisty 

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.


@section DESCRIPTION

View and key mapping for Radia. 

*/
using UnityEngine;
using UnityEngine.UI;
using UnityEngine.EventSystems;
using System.Collections;

[AddComponentMenu("Camera-Control/Move ZeroG")]
public class CameraControlZeroG : MonoBehaviour {
	public float speed = 100.0f;

	private GameController controller;
	private Vector3 move = new Vector3();
	private Vector3 start_pos = new Vector3(0, 0, -800);
	private Vector3 target;
	private GameObject target_object;
	private bool follow = false;

	public void SetFocus (Function node) {
		target = node.transform.position + (transform.forward * -50f);
		target_object = node.gameObject;
		follow = true;
	}

	void Start(){
		controller = GameObject.Find ("GameController").GetComponent<GameController> ();
		transform.position = start_pos;
	}
	// Sets controls for selecting nodes and interacting with the UI
	void Update () {
		if (controller.InputActive ()) {
			move.x = Input.GetAxis ("Horizontal") * speed * Time.deltaTime;
			move.z = Input.GetAxis ("Vertical") * speed * Time.deltaTime;
			move.y = Input.GetAxis ("UpDown") * speed * Time.deltaTime;

			if (Input.GetKeyDown ("p")) {
				controller.ToggleFDGCalc();
			}

			if (Input.GetKeyDown ("m") && controller.GetUIActive ()) {
				controller.EditMark();
			} else if (Input.GetKeyDown ("m") && !(controller.GetUIActive())) {
				controller.ShowMarkList();
			}

			if (Input.GetKeyDown (";") && controller.GetUIActive ()) {
				controller.EditComment();
			}

			if (Input.GetKeyDown ("n") && controller.GetUIActive ()) {
				controller.EditFunctionName();
			}

			if (Input.GetKeyDown ("l")) {
				controller.ToggleLegend();
			}

			if (Input.GetKeyDown ("z") && controller.GetUIActive ()) {
				SetFocus (controller.GetSelectedFunction());
			}

			if (Input.GetKeyDown (KeyCode.Escape) && !(controller.GetUIActive ())) {
				if (controller.quit_dialog.activeInHierarchy) {
					controller.quit_dialog.SetActive(false);
				} else {
					controller.quit_dialog.SetActive(true);
				}
			}

			if (Input.GetKeyDown("q") && controller.quit_dialog.activeInHierarchy) {
				controller.Cleanup();
				Application.LoadLevel("MainMenu");
			}
		}

		if (controller.mark_list.activeSelf) {
			if (Input.GetKeyDown (KeyCode.DownArrow)) {
				controller.ui.SelectNextMark ();
			}

			if (Input.GetKeyDown (KeyCode.UpArrow)) {
				controller.ui.SelectPreviousMark ();
			}

			if (Input.GetKeyDown (KeyCode.Return) || Input.GetKeyDown (KeyCode.Space)) {
				controller.ui.SelectMark ();
			}
			if (Input.GetKeyDown (KeyCode.Escape)) {
				controller.HideMarkList ();
			}
		} else {
			if (Input.GetKeyDown (KeyCode.Escape)) {
				controller.SetUIActive (false);
			}
		}

		move = transform.TransformDirection(move);
		transform.position += move;

		if (follow) {
			Vector3 position = Vector3.Lerp(transform.position, target, Time.deltaTime * 5f);
			transform.position = position;
			if (Vector3.Distance(transform.position, target) < 1f) {
				follow = false;
				// controller.HideMarkList ();
				// controller.SelectFunction(target_object);
			}
		}
	}
}